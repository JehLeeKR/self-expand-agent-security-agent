"""Main CLI entry point for the AI Threat Defense Agent."""

import argparse
import asyncio
import sys
from pathlib import Path

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.db.models import init_db, get_session
from src.db.result_store import ResultStore
from src.db.threat_store import ThreatStore
from src.utils.logging import setup_logging, get_logger

console = Console()


def load_config(config_path: str) -> dict:
    """Load YAML configuration from the given path."""
    path = Path(config_path)
    if not path.exists():
        console.print(f"[red]Configuration file not found:[/red] {config_path}")
        sys.exit(1)
    with open(path) as f:
        return yaml.safe_load(f)


def load_sources_config(project_root: Path) -> dict:
    """Load threat intelligence source definitions."""
    sources_path = project_root / "config" / "sources.yaml"
    if sources_path.exists():
        with open(sources_path) as f:
            return yaml.safe_load(f) or {}
    return {}


def load_victim_profiles(project_root: Path) -> dict:
    """Load victim profiles configuration."""
    profiles_path = project_root / "config" / "victim_profiles.yaml"
    if profiles_path.exists():
        with open(profiles_path) as f:
            return yaml.safe_load(f) or {}
    return {}


def init_stores(config: dict) -> tuple[ThreatStore, ResultStore]:
    """Initialize database sessions and return store instances."""
    db_config = config.get("database", {})

    threats_db = db_config.get("threats_db", "./data/threats.db")
    results_db = db_config.get("results_db", "./data/results.db")

    # Ensure data directory exists
    Path(threats_db).parent.mkdir(parents=True, exist_ok=True)
    Path(results_db).parent.mkdir(parents=True, exist_ok=True)

    threats_session_factory = init_db(threats_db)
    results_session_factory = init_db(results_db)

    threat_store = ThreatStore(get_session(threats_session_factory))
    result_store = ResultStore(get_session(results_session_factory))

    return threat_store, result_store


def cmd_collect(config: dict, threat_store: ThreatStore, result_store: ResultStore) -> None:
    """Run threat collection from all sources."""
    from src.collector.manager import CollectorManager

    console.print(Panel("Collecting threat intelligence from all sources", style="bold blue"))

    # Merge sources.yaml into config so collectors can find their keys
    sources = load_sources_config(Path.cwd())
    collector_config = {**config, **sources}

    manager = CollectorManager(threat_store, collector_config)
    new_count = asyncio.run(manager.run())

    console.print(f"[green]Collection complete:[/green] {new_count} new threat(s) added")


def cmd_analyze(config: dict, threat_store: ThreatStore, result_store: ResultStore) -> None:
    """Classify, plan defenses, and generate tests for unprocessed threats."""
    from src.analyzer.threat_classifier import ThreatClassifier
    from src.analyzer.defense_planner import DefensePlanner
    from src.analyzer.test_generator import TestGenerator
    from src.utils.claude_api import ClaudeAPI

    console.print(Panel("Analyzing unprocessed threats", style="bold blue"))

    api_config = config.get("claude_api", {})
    claude_api = ClaudeAPI(
        model=api_config.get("model", "claude-sonnet-4-6"),
        max_tokens=api_config.get("max_tokens", 4096),
    )

    # Step 1: Classify
    console.print("[bold]Step 1:[/bold] Classifying threats...")
    classifier = ThreatClassifier(claude_api, threat_store, result_store)
    classified = classifier.run()
    console.print(f"  Classified: {classified} threat(s)")

    # Step 2: Plan defenses
    console.print("[bold]Step 2:[/bold] Planning defenses...")
    planner = DefensePlanner(claude_api, threat_store, result_store)
    planned = planner.run()
    console.print(f"  Planned: {planned} defense(s)")

    # Step 3: Generate test payloads
    console.print("[bold]Step 3:[/bold] Generating test payloads...")
    generator = TestGenerator(claude_api, threat_store)
    generated = generator.run()
    console.print(f"  Generated tests for: {generated} threat(s)")

    console.print(
        f"[green]Analysis complete:[/green] "
        f"{classified} classified, {planned} planned, {generated} test suites generated"
    )


def cmd_implement(config: dict, threat_store: ThreatStore, result_store: ResultStore) -> None:
    """Implement defense layers for planned threats."""
    from src.defender.implementer import DefenseImplementer
    from src.defender.layer_registry import LayerRegistry
    from src.utils.claude_code import ClaudeCode

    console.print(Panel("Implementing defense layers", style="bold blue"))

    code_config = config.get("claude_code", {})
    claude_code = ClaudeCode(
        binary=code_config.get("binary", "claude"),
        working_dir=code_config.get("working_dir", "./src/defender/layers"),
        timeout=code_config.get("timeout_seconds", 300),
    )

    layer_registry = LayerRegistry(result_store)
    implementer = DefenseImplementer(
        claude_code, layer_registry, threat_store, result_store, config
    )
    implemented = implementer.run()

    console.print(f"[green]Implementation complete:[/green] {implemented} layer(s) implemented")


def cmd_test(config: dict, threat_store: ThreatStore, result_store: ResultStore) -> None:
    """Run red team tests against all unaddressed threats."""
    from src.defender.layer_registry import LayerRegistry
    from src.sandbox.docker_manager import DockerManager
    from src.tester.attack_runner import AttackRunner
    from src.tester.evaluator import DefenseEvaluator

    console.print(Panel("Running red team tests", style="bold blue"))

    docker_config = config.get("docker", {})
    docker_manager = DockerManager(docker_config)
    layer_registry = LayerRegistry(result_store)
    evaluator = DefenseEvaluator(result_store)

    victim_profiles = load_victim_profiles(Path.cwd())
    test_config = {**config, "victim_profiles": victim_profiles}

    attack_runner = AttackRunner(docker_manager, layer_registry, threat_store, test_config)

    # Get threats that need testing (planned or implemented but not yet fully tested)
    threats_to_test = (
        threat_store.get_threats_by_status("planned")
        + threat_store.get_threats_by_status("implemented")
    )

    if not threats_to_test:
        console.print("[yellow]No threats to test.[/yellow]")
        return

    console.print(f"Testing {len(threats_to_test)} threat(s)...")

    run_ids: list[str] = []
    table = Table(title="Test Results")
    table.add_column("Threat ID", style="cyan", max_width=12)
    table.add_column("Category")
    table.add_column("Profile")
    table.add_column("Detection", justify="right")
    table.add_column("Prevention", justify="right")
    table.add_column("Leaked", justify="right")

    profiles = list(victim_profiles.get("profiles", {}).keys())
    if not profiles:
        profiles = ["corporate_assistant", "code_agent", "data_analyst"]

    for threat in threats_to_test:
        for profile in profiles:
            try:
                defended = attack_runner.run_attack(threat, profile, with_defenses=True)
                test_run = evaluator.run(defended, threat.id, profile)
                run_ids.append(test_run.id)

                table.add_row(
                    threat.id[:10] + "...",
                    threat.category,
                    profile,
                    f"{test_run.detection_rate:.0%}",
                    f"{test_run.prevention_rate:.0%}",
                    f"{test_run.exfiltration_rate:.0%}",
                )
            except Exception as exc:
                console.print(
                    f"[red]Test failed for {threat.id[:10]}... / {profile}:[/red] {exc}"
                )

        # Update threat status to tested
        threat_store.update_threat_status(threat.id, "tested")

    console.print(table)
    console.print(f"[green]Testing complete:[/green] {len(run_ids)} test run(s) recorded")


def cmd_optimize(config: dict, threat_store: ThreatStore, result_store: ResultStore) -> None:
    """Run defense stack optimization."""
    from src.defender.layer_registry import LayerRegistry
    from src.defender.optimizer import DefenseOptimizer

    console.print(Panel("Optimizing defense stack", style="bold blue"))

    layer_registry = LayerRegistry(result_store)
    optimizer = DefenseOptimizer(layer_registry, result_store)
    report = optimizer.run()

    if report:
        table = Table(title="Optimization Results")
        table.add_column("Metric")
        table.add_column("Value", justify="right")
        for key, value in report.items():
            if isinstance(value, float):
                table.add_row(key, f"{value:.2%}")
            else:
                table.add_row(key, str(value))
        console.print(table)
    else:
        console.print("[yellow]No optimization data returned.[/yellow]")

    console.print("[green]Optimization complete.[/green]")


def cmd_integrity(config: dict, threat_store: ThreatStore, result_store: ResultStore) -> None:
    """Run integrity verification on all defense layers."""
    from src.defender.integrity import IntegrityVerifier
    from src.utils.claude_code import ClaudeCode

    console.print(Panel("Running integrity verification", style="bold red"))

    code_config = config.get("claude_code", {})
    claude_code = ClaudeCode(
        binary=code_config.get("binary", "claude"),
        timeout=code_config.get("timeout_seconds", 300),
    )

    verifier = IntegrityVerifier(claude_code, result_store, config)
    report = verifier.run()

    preflight = report.get("preflight", {})
    if preflight.get("all_safe"):
        console.print("[green]All layers passed integrity checks[/green]")
    else:
        console.print("[red]INTEGRITY ISSUES DETECTED[/red]")
        for name, result in preflight.get("results", {}).items():
            status = result.get("status", "unknown")
            style = "green" if status == "ok" else "red"
            console.print(f"  [{style}]{name}: {status}[/{style}]")

    audits = report.get("deep_audits", {})
    if audits:
        console.print(f"\n[bold]Deep audits performed:[/bold] {len(audits)}")
        for name, audit in audits.items():
            score = audit.get("score", 0)
            style = "green" if score >= 0.8 else "yellow" if score >= 0.5 else "red"
            console.print(f"  [{style}]{name}: score={score:.2f}[/{style}]")


def cmd_review(config: dict, threat_store: ThreatStore, result_store: ResultStore) -> None:
    """Run periodic code review on defense layers."""
    from src.defender.reviewer import PeriodicReviewer
    from src.utils.claude_code import ClaudeCode

    console.print(Panel("Running periodic review", style="bold blue"))

    code_config = config.get("claude_code", {})
    claude_code = ClaudeCode(
        binary=code_config.get("binary", "claude"),
        timeout=code_config.get("timeout_seconds", 300),
    )

    reviewer = PeriodicReviewer(claude_code, result_store, config)
    report = reviewer.run()

    reviews = report.get("reviews", [])
    fixes = report.get("auto_fixes", [])
    console.print(f"[green]Reviews complete:[/green] {len(reviews)} review(s), {len(fixes)} auto-fix(es)")

    for r in reviews:
        findings_count = len(r.get("findings", {}).get("findings", []))
        console.print(f"  {r['layer']} ({r['type']}): {findings_count} finding(s)")


def cmd_adapt(config: dict, threat_store: ThreatStore, result_store: ResultStore) -> None:
    """Run self-learning adaptation on defense layers."""
    from src.defender.self_learner import SelfLearner
    from src.utils.claude_code import ClaudeCode

    console.print(Panel("Running self-learning adaptation", style="bold cyan"))

    code_config = config.get("claude_code", {})
    claude_code = ClaudeCode(
        binary=code_config.get("binary", "claude"),
        timeout=code_config.get("timeout_seconds", 300),
    )

    learner = SelfLearner(claude_code, result_store, config)
    results = learner.run()

    console.print(f"[green]Adaptation complete:[/green] {len(results)} layer(s) adapted")
    for r in results:
        console.print(f"  {r['layer']}: {len(r['adaptations'])} adaptation(s)")


def cmd_morph(config: dict, threat_store: ThreatStore, result_store: ResultStore) -> None:
    """Run metamorphic transformation on defense layers."""
    from src.defender.metamorphic import MetamorphicEngine
    from src.utils.claude_code import ClaudeCode

    console.print(Panel("Running metamorphic transformations", style="bold magenta"))

    code_config = config.get("claude_code", {})
    claude_code = ClaudeCode(
        binary=code_config.get("binary", "claude"),
        timeout=code_config.get("timeout_seconds", 300),
    )

    engine = MetamorphicEngine(claude_code, result_store, config)
    results = engine.run()

    console.print(f"[green]Metamorphic cycle complete:[/green] {len(results)} layer(s) transformed")
    for r in results:
        console.print(f"  {r['layer']}: {r['morph_type']}")


def cmd_staging(config: dict, threat_store: ThreatStore, result_store: ResultStore) -> None:
    """Evaluate staging pipeline and promote/reject layers."""
    from src.defender.staging import StagingPipeline

    console.print(Panel("Evaluating staging pipeline", style="bold yellow"))

    pipeline = StagingPipeline(result_store, config)
    result = pipeline.evaluate_promotions()

    promoted = result.get("promoted", [])
    rejected = result.get("rejected", [])
    unchanged = result.get("unchanged", [])

    if promoted:
        for p in promoted:
            console.print(f"  [green]PROMOTED:[/green] {p['layer']} → {p['to_stage']}")
    if rejected:
        for r in rejected:
            console.print(f"  [red]REJECTED:[/red] {r['layer']} — {r.get('reason', '')}")
    if unchanged:
        for u in unchanged:
            console.print(f"  [dim]{u['layer']}: {u['stage']}[/dim]")

    console.print(
        f"[green]Staging evaluation:[/green] "
        f"{len(promoted)} promoted, {len(rejected)} rejected, {len(unchanged)} unchanged"
    )


def cmd_variants(config: dict, threat_store: ThreatStore, result_store: ResultStore) -> None:
    """Show variant twin status and rotate active variants."""
    from src.defender.variant_manager import VariantManager
    from src.defender.layer_registry import LayerRegistry
    from src.utils.claude_code import ClaudeCode

    console.print(Panel("Variant twin status", style="bold blue"))

    code_config = config.get("claude_code", {})
    claude_code = ClaudeCode(
        binary=code_config.get("binary", "claude"),
        timeout=code_config.get("timeout_seconds", 300),
    )
    layer_registry = LayerRegistry(result_store)
    mgr = VariantManager(claude_code, layer_registry, result_store, config)

    status = mgr.get_variant_status()
    if not status:
        console.print("[yellow]No variant groups found.[/yellow]")
        return

    table = Table(title="Variant Twins")
    table.add_column("Category")
    table.add_column("Active Variant")
    table.add_column("Strategy")
    table.add_column("Variants", justify="right")
    table.add_column("Rotation")

    for category, info in status.items():
        table.add_row(
            category,
            info.get("active_variant", "none"),
            next(
                (v["strategy"] for v in info.get("variants", []) if v["is_active"]),
                "—",
            ),
            str(len(info.get("variants", []))),
            info.get("rotation_strategy", "round_robin"),
        )

    console.print(table)


def cmd_council(config: dict, threat_store: ThreatStore, result_store: ResultStore) -> None:
    """Show multi-agent council session history and status."""
    from src.defender.council_manager import CouncilManager
    from src.utils.claude_code import ClaudeCode

    console.print(Panel("Multi-Agent Council Status", style="bold blue"))

    code_config = config.get("claude_code", {})
    claude_code = ClaudeCode(
        binary=code_config.get("binary", "claude"),
        timeout=code_config.get("timeout_seconds", 300),
    )

    council = CouncilManager(claude_code, result_store, config)
    history = council.get_session_history(limit=10)

    if not history:
        console.print("[yellow]No council sessions recorded yet.[/yellow]")
        council_config = config.get("council", {})
        enabled = council_config.get("enabled", True)
        console.print(f"Council mode: {'[green]enabled[/green]' if enabled else '[red]disabled[/red]'}")
        console.print(f"Max rounds: {council_config.get('max_rounds', 3)}")
        console.print(f"Required approvals: {council_config.get('required_approvals', 3)}")
        return

    table = Table(title="Recent Council Sessions")
    table.add_column("Session", max_width=12)
    table.add_column("Layer")
    table.add_column("Decision")
    table.add_column("Rounds", justify="right")
    table.add_column("Votes")
    table.add_column("Time")

    for s in history:
        decision = s.get("decision", "unknown")
        style = "green" if decision == "approve" else "red" if decision == "reject" else "yellow"

        votes = s.get("votes", [])
        vote_summary = ", ".join(
            f"{v['agent'][:3]}:{v['vote'][:1].upper()}" for v in votes
        )

        table.add_row(
            s["session_id"][:10] + "...",
            s.get("layer", "?"),
            f"[{style}]{decision}[/{style}]",
            str(s.get("rounds", 0)),
            vote_summary,
            s.get("started_at", "")[:19],
        )

    console.print(table)


def cmd_cycle(config: dict, threat_store: ThreatStore, result_store: ResultStore) -> None:
    """Run the full pipeline with robustness: collect → analyze → implement → test → optimize → review → adapt → staging."""
    console.print(Panel("Running full defense cycle (with robustness)", style="bold magenta"))

    steps = [
        ("Collect", cmd_collect),
        ("Analyze", cmd_analyze),
        ("Integrity Check", cmd_integrity),
        ("Implement", cmd_implement),
        ("Test", cmd_test),
        ("Staging Evaluation", cmd_staging),
        ("Optimize", cmd_optimize),
        ("Self-Learn & Adapt", cmd_adapt),
        ("Periodic Review", cmd_review),
        ("Metamorphic Transform", cmd_morph),
    ]

    for step_name, step_fn in steps:
        console.print(f"\n[bold]--- {step_name} ---[/bold]\n")
        try:
            step_fn(config, threat_store, result_store)
        except Exception as exc:
            console.print(f"[red]Step '{step_name}' failed:[/red] {exc}")
            logger = get_logger()
            logger.exception(
                f"Pipeline step failed: {step_name}",
                extra={"extra_data": {"step": step_name, "error": str(exc)}},
            )
            console.print("[yellow]Continuing to next step...[/yellow]")

    console.print(Panel("[green]Full cycle complete (with robustness)[/green]", style="bold green"))


def cmd_report(config: dict, threat_store: ThreatStore, result_store: ResultStore) -> None:
    """Generate and print the dashboard report."""
    from src.tester.report import ReportGenerator

    console.print(Panel("Generating dashboard report", style="bold blue"))

    report_gen = ReportGenerator(result_store, threat_store)
    dashboard = report_gen.generate_dashboard()

    from rich.markdown import Markdown
    console.print(Markdown(dashboard))


def cmd_status(config: dict, threat_store: ThreatStore, result_store: ResultStore) -> None:
    """Show current system status."""
    console.print(Panel("System Status", style="bold blue"))

    # Threat counts
    unclassified = threat_store.get_unclassified_threats()
    all_classified = threat_store.get_all_classified()

    status_counts: dict[str, int] = {}
    for threat in all_classified:
        status = threat.status or "unknown"
        status_counts[status] = status_counts.get(status, 0) + 1

    threats_table = Table(title="Threat Intelligence")
    threats_table.add_column("Metric")
    threats_table.add_column("Count", justify="right")
    threats_table.add_row("Raw (unclassified)", str(len(unclassified)))
    threats_table.add_row("Total classified", str(len(all_classified)))
    for status, count in sorted(status_counts.items()):
        threats_table.add_row(f"  Status: {status}", str(count))
    console.print(threats_table)

    # Active defense layers
    active_layers = result_store.get_active_layers()
    layers_table = Table(title="Active Defense Layers")
    layers_table.add_column("Layer")
    layers_table.add_column("Priority", justify="right")
    layers_table.add_column("Effectiveness", justify="right")
    layers_table.add_column("Categories")

    for layer in active_layers:
        categories = ", ".join(layer.get_threat_categories())
        layers_table.add_row(
            layer.name,
            str(layer.priority),
            f"{layer.effectiveness_score:.0%}",
            categories,
        )

    if not active_layers:
        layers_table.add_row("(none)", "-", "-", "-")

    console.print(layers_table)

    # Latest test runs
    latest_runs = result_store.get_latest_runs(limit=5)
    runs_table = Table(title="Latest Test Runs")
    runs_table.add_column("Run ID", max_width=12)
    runs_table.add_column("Threat", max_width=12)
    runs_table.add_column("Profile")
    runs_table.add_column("Detection", justify="right")
    runs_table.add_column("Prevention", justify="right")
    runs_table.add_column("Time")

    for run in latest_runs:
        runs_table.add_row(
            run.id[:10] + "...",
            run.threat_id[:10] + "...",
            run.victim_profile,
            f"{run.detection_rate:.0%}",
            f"{run.prevention_rate:.0%}",
            str(run.run_at),
        )

    if not latest_runs:
        runs_table.add_row("(none)", "-", "-", "-", "-", "-")

    console.print(runs_table)

    # Database paths
    db_config = config.get("database", {})
    console.print(f"\n[dim]Threats DB:[/dim] {db_config.get('threats_db', 'N/A')}")
    console.print(f"[dim]Results DB:[/dim] {db_config.get('results_db', 'N/A')}")


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="threat-defense",
        description="AI Threat Defense Agent - Autonomous threat collection, analysis, and defense",
    )
    parser.add_argument(
        "--config",
        default="config/default.yaml",
        help="Path to the YAML configuration file (default: config/default.yaml)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Part 1: Claude CLI — Intelligence
    subparsers.add_parser("collect", help="Run threat collection from all sources")
    subparsers.add_parser("analyze", help="Classify, plan, and generate tests for unprocessed threats")

    # Part 2: Claude Code CLI — Implementation (with multi-agent council)
    subparsers.add_parser("implement", help="Implement defense layers via multi-agent council")
    subparsers.add_parser("variants", help="Show variant twin status")
    subparsers.add_parser("council", help="Show multi-agent council session history")

    # Part 3: Claude Code CLI — Management / CI-CD
    subparsers.add_parser("test", help="Run red team tests against all unaddressed threats")
    subparsers.add_parser("optimize", help="Run defense stack optimization")
    subparsers.add_parser("integrity", help="Run integrity verification on all defense layers")
    subparsers.add_parser("review", help="Run periodic code review via Claude Code CLI")
    subparsers.add_parser("adapt", help="Run self-learning adaptation on defense layers")
    subparsers.add_parser("morph", help="Run metamorphic transformation on defense layers")
    subparsers.add_parser("staging", help="Evaluate staging pipeline promotions/rejections")

    # Full cycle & reporting
    subparsers.add_parser("cycle", help="Run the full pipeline with robustness")
    subparsers.add_parser("report", help="Generate and print the dashboard report")
    subparsers.add_parser("status", help="Show current system status")

    return parser


COMMANDS = {
    # Part 1: Claude CLI — Intelligence
    "collect": cmd_collect,
    "analyze": cmd_analyze,
    # Part 2: Claude Code CLI — Implementation (with multi-agent council)
    "implement": cmd_implement,
    "variants": cmd_variants,
    "council": cmd_council,
    # Part 3: Claude Code CLI — Management / CI-CD
    "test": cmd_test,
    "optimize": cmd_optimize,
    "integrity": cmd_integrity,
    "review": cmd_review,
    "adapt": cmd_adapt,
    "morph": cmd_morph,
    "staging": cmd_staging,
    # Full cycle & reporting
    "cycle": cmd_cycle,
    "report": cmd_report,
    "status": cmd_status,
}


def cli() -> None:
    """Main CLI entry point referenced in pyproject.toml."""
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Load configuration
    config = load_config(args.config)

    # Setup logging
    log_config = config.get("logging", {})
    setup_logging(
        level=log_config.get("level", "INFO"),
        log_file=log_config.get("file"),
    )

    logger = get_logger()
    logger.info(
        "CLI invoked",
        extra={"extra_data": {"command": args.command, "config": args.config}},
    )

    # Initialize stores
    try:
        threat_store, result_store = init_stores(config)
    except Exception as exc:
        console.print(f"[red]Failed to initialize database:[/red] {exc}")
        sys.exit(1)

    # Dispatch command
    command_fn = COMMANDS.get(args.command)
    if command_fn is None:
        console.print(f"[red]Unknown command:[/red] {args.command}")
        parser.print_help()
        sys.exit(1)

    try:
        command_fn(config, threat_store, result_store)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        sys.exit(130)
    except Exception as exc:
        logger.exception(
            "Command failed",
            extra={"extra_data": {"command": args.command, "error": str(exc)}},
        )
        console.print(f"[red]Command '{args.command}' failed:[/red] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    cli()
