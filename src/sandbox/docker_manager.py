"""Manages Docker containers for isolated victim agent environments."""

import io
import os
import tarfile
import time

import docker
import requests

from src.utils.logging import get_logger

logger = get_logger()


class DockerManager:
    """Build, run, and manage Docker containers hosting victim agents."""

    def __init__(self, config: dict):
        """Initialize with the ``docker`` section of default.yaml."""
        self.config = config
        self.victim_image_name = config.get("victim_image", "threat-defense-victim:latest")
        self.network_name = config.get("network", "isolated")
        self.memory_limit = config.get("memory_limit", "512m")
        self.cpu_limit = float(config.get("cpu_limit", "1.0"))
        self.client = docker.from_env()
        self._containers: list[str] = []
        self._images: list[str] = []

    # ------------------------------------------------------------------
    # Image management
    # ------------------------------------------------------------------

    def build_image(self, profile_name: str, seed_data: dict) -> str:
        """Build a Docker image with seed data baked in.

        *seed_data* should have the shape returned by
        ``SeedDataGenerator.generate_all()``  -- ``{"files": {path: content}, "sql": str}``.

        Returns the image ID.
        """
        dockerfile_dir = os.path.join(os.path.dirname(__file__), "..", "..", "docker")
        dockerfile_dir = os.path.abspath(dockerfile_dir)

        # Copy victim_entrypoint.py next to the Dockerfile so the COPY instruction works
        entrypoint_src = os.path.join(
            os.path.dirname(__file__), "victim_agent.py"
        )
        entrypoint_dst = os.path.join(dockerfile_dir, "victim_entrypoint.py")
        with open(entrypoint_src, "r") as f_in, open(entrypoint_dst, "w") as f_out:
            f_out.write(f_in.read())

        tag = f"threat-defense-victim-{profile_name}:latest"
        logger.info(
            "Building victim image",
            extra={"extra_data": {"profile": profile_name, "tag": tag}},
        )

        image, build_logs = self.client.images.build(
            path=dockerfile_dir,
            dockerfile="Dockerfile.victim",
            tag=tag,
            rm=True,
        )

        for chunk in build_logs:
            if "stream" in chunk:
                logger.debug(chunk["stream"].strip())

        self._images.append(image.id)

        # Now create a temporary container to inject seed data, then commit.
        container = self.client.containers.create(image.id, command="sleep 3600", user="root")
        container.start()

        try:
            self._inject_seed_data(container, seed_data)
            # Fix ownership
            container.exec_run("chown -R victim:victim /home/victim", user="root")
            # Commit container with seed data as a new image
            committed = container.commit(repository=tag)
            self._images.append(committed.id)
            logger.info("Committed seeded image", extra={"extra_data": {"image_id": committed.short_id}})
            return committed.id
        finally:
            container.stop()
            container.remove(force=True)

    def _inject_seed_data(self, container: "docker.models.containers.Container", seed_data: dict) -> None:
        """Write seed files and execute seed SQL inside *container*."""
        files: dict[str, str] = seed_data.get("files", {})
        sql: str = seed_data.get("sql", "")

        # Upload files via tar archive
        if files:
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w") as tar:
                for path, content in files.items():
                    data = content.encode("utf-8")
                    info = tarfile.TarInfo(name=path.lstrip("/"))
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
            buf.seek(0)
            container.put_archive("/", buf)
            logger.info("Injected seed files", extra={"extra_data": {"count": len(files)}})

        # Seed the SQLite database
        if sql:
            db_path = "/home/victim/db/victim.db"
            container.exec_run(f"mkdir -p /home/victim/db", user="root")
            # Write SQL to a temp file and pipe through sqlite3
            sql_bytes = sql.encode("utf-8")
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w") as tar:
                info = tarfile.TarInfo(name="tmp/seed.sql")
                info.size = len(sql_bytes)
                tar.addfile(info, io.BytesIO(sql_bytes))
            buf.seek(0)
            container.put_archive("/", buf)
            exit_code, output = container.exec_run(
                f'sh -c "sqlite3 {db_path} < /tmp/seed.sql"', user="root"
            )
            if exit_code != 0:
                logger.error("Seed SQL failed", extra={"extra_data": {"output": output.decode()}})
            else:
                logger.info("Seeded SQLite database", extra={"extra_data": {"db": db_path}})

    # ------------------------------------------------------------------
    # Container lifecycle
    # ------------------------------------------------------------------

    def start_container(self, profile_name: str, image_id: str) -> str:
        """Start a victim container from the given image, returning the container ID."""
        self._ensure_network()

        container_name = f"victim-{profile_name}-{int(time.time())}"
        logger.info(
            "Starting victim container",
            extra={"extra_data": {"profile": profile_name, "image": image_id}},
        )

        container = self.client.containers.run(
            image_id,
            name=container_name,
            detach=True,
            mem_limit=self.memory_limit,
            nano_cpus=int(self.cpu_limit * 1e9),
            network=self.network_name,
            environment={
                "VICTIM_PROFILE": profile_name,
                "ANTHROPIC_API_KEY": os.environ.get("ANTHROPIC_API_KEY", ""),
            },
            ports={"8080/tcp": None},  # random host port
        )

        self._containers.append(container.id)

        # Wait for the health endpoint to become available
        self._wait_for_healthy(container)

        logger.info(
            "Victim container started",
            extra={"extra_data": {"container_id": container.short_id, "name": container_name}},
        )
        return container.id

    def stop_container(self, container_id: str) -> None:
        """Stop and remove a container."""
        try:
            container = self.client.containers.get(container_id)
            container.stop(timeout=10)
            container.remove(force=True)
            if container_id in self._containers:
                self._containers.remove(container_id)
            logger.info("Stopped container", extra={"extra_data": {"container_id": container_id[:12]}})
        except docker.errors.NotFound:
            logger.warning("Container not found", extra={"extra_data": {"container_id": container_id[:12]}})

    def execute_in_container(self, container_id: str, command: str) -> str:
        """Execute a command inside the container and return stdout."""
        container = self.client.containers.get(container_id)
        exit_code, output = container.exec_run(command, user="victim")
        decoded = output.decode("utf-8", errors="replace")
        if exit_code != 0:
            logger.warning(
                "Command exited with non-zero code",
                extra={"extra_data": {"exit_code": exit_code, "command": command[:120]}},
            )
        return decoded

    def send_to_victim(self, container_id: str, message: str) -> str:
        """Send a chat message to the victim agent API running inside the container.

        Returns the agent's response text.
        """
        container = self.client.containers.get(container_id)
        container.reload()  # refresh port mapping info

        ports = container.attrs["NetworkSettings"]["Ports"].get("8080/tcp")
        if not ports:
            raise RuntimeError(f"No port mapping found for container {container_id[:12]}")
        host_port = ports[0]["HostPort"]

        url = f"http://127.0.0.1:{host_port}/chat"
        try:
            resp = requests.post(url, json={"message": message}, timeout=120)
            resp.raise_for_status()
            return resp.json().get("response", "")
        except requests.RequestException as exc:
            logger.error("Failed to contact victim agent", extra={"extra_data": {"error": str(exc)}})
            raise

    def get_container_logs(self, container_id: str) -> str:
        """Return all logs for a container."""
        container = self.client.containers.get(container_id)
        return container.logs().decode("utf-8", errors="replace")

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def cleanup(self) -> None:
        """Remove all tracked victim containers and images."""
        for cid in list(self._containers):
            try:
                self.stop_container(cid)
            except Exception as exc:
                logger.warning("Cleanup: failed to stop container", extra={"extra_data": {"error": str(exc)}})

        for iid in list(self._images):
            try:
                self.client.images.remove(iid, force=True)
                logger.info("Removed image", extra={"extra_data": {"image_id": iid[:12]}})
            except Exception as exc:
                logger.warning("Cleanup: failed to remove image", extra={"extra_data": {"error": str(exc)}})

        self._containers.clear()
        self._images.clear()
        logger.info("Cleanup complete")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_network(self) -> None:
        """Create the isolated Docker network if it doesn't exist."""
        try:
            self.client.networks.get(self.network_name)
        except docker.errors.NotFound:
            self.client.networks.create(
                self.network_name,
                driver="bridge",
                internal=True,  # no external internet access
            )
            logger.info("Created isolated network", extra={"extra_data": {"network": self.network_name}})

    def _wait_for_healthy(self, container: "docker.models.containers.Container", timeout: int = 30) -> None:
        """Poll the container's health endpoint until it responds or *timeout* seconds elapse."""
        container.reload()
        ports = container.attrs["NetworkSettings"]["Ports"].get("8080/tcp")
        if not ports:
            logger.warning("Container has no mapped port, skipping health check")
            return

        host_port = ports[0]["HostPort"]
        url = f"http://127.0.0.1:{host_port}/health"
        deadline = time.time() + timeout

        while time.time() < deadline:
            try:
                resp = requests.get(url, timeout=2)
                if resp.status_code == 200:
                    return
            except requests.ConnectionError:
                pass
            time.sleep(1)

        logger.warning("Health check timed out", extra={"extra_data": {"timeout": timeout}})
