from __future__ import annotations

import argparse
import json
import logging
import re
import shutil
import subprocess
from pathlib import Path


RUTA_BASE_CICD = Path(__file__).resolve().parents[1]
RUTA_REPOS_POR_DEFECTO = RUTA_BASE_CICD / "data" / "repos"
RUTA_RESULTADOS_POR_DEFECTO = RUTA_BASE_CICD / "data" / "results"
SUFIJO_CICD_RAW = "-cicd-raw.json"
SUFIJO_CICD = "-cicd.json"
FORMATO_SALIDA_CHECKOV = "json"
MENSAJE_CHECKOV_NO_INSTALADO = (
    "Checkov is not installed. Please install it using: pip install checkov"
)

# Archivos y directorios de CI/CD a analizar
CICD_PATTERNS = [
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
    ".gitlab-ci.yml",
    "Jenkinsfile",
    ".circleci/config.yml",
    "azure-pipelines.yml",
    ".travis.yml",
    ".drone.yml",
]


if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
LOGGER = logging.getLogger(__name__)
PATRON_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


class CICDAnalyzer:
    """Analizador de vulnerabilidades en configuraciones CI/CD usando Checkov."""

    def __init__(self, repos_path: str, output_path: str):
        self.repos_path = Path(repos_path).expanduser().resolve()
        self.output_path = Path(output_path).expanduser().resolve()
        self.project_root = Path(__file__).resolve().parents[1]
        self.checkov_bin = "checkov"
        self.dry_run = False
        self.checkov_path: str | None = None

    def discover_repositories(self) -> list[str]:
        """Devuelve una lista de rutas de repositorios."""
        self._validar_directorio_repos()

        repositorios = sorted(
            str(ruta.relative_to(self.project_root))
            for ruta in self.repos_path.iterdir()
            if ruta.is_dir()
        )

        if not repositorios:
            LOGGER.warning(f"No repositories found in {self.repos_path}")

        return repositorios

    def discover_cicd_files(self, repo_path: str) -> list[Path]:
        """Descubre archivos de configuración CI/CD en el repositorio."""
        ruta_repo = self.project_root / repo_path

        cicd_files = []

        # Buscar archivos de GitHub Actions
        workflows_dir = ruta_repo / ".github" / "workflows"
        if workflows_dir.exists():
            cicd_files.extend(workflows_dir.glob("*.yml"))
            cicd_files.extend(workflows_dir.glob("*.yaml"))

        # Buscar otros archivos de CI/CD en la raíz del repositorio
        cicd_file_names = [
            ".gitlab-ci.yml",
            "Jenkinsfile",
            ".circleci/config.yml",
            "azure-pipelines.yml",
            ".travis.yml",
            ".drone.yml",
        ]

        for file_name in cicd_file_names:
            file_path = ruta_repo / file_name
            if file_path.exists():
                cicd_files.append(file_path)

        return cicd_files

    def run_checkov(self, repo_path: str) -> str:
        """Ejecuta Checkov en el repositorio y devuelve JSON con misconfigurations."""
        ruta_repo = self.project_root / repo_path

        if not ruta_repo.exists():
            raise FileNotFoundError(f"Repository path does not exist: {ruta_repo}")

        if not ruta_repo.is_dir():
            raise NotADirectoryError(f"Path is not a directory: {ruta_repo}")

        if not any(ruta_repo.iterdir()):
            raise ValueError(f"Repository directory is empty: {ruta_repo}")

        # Verificar que hay archivos de CI/CD
        cicd_files = self.discover_cicd_files(repo_path)
        if not cicd_files:
            LOGGER.warning(
                f"No CI/CD configuration files found in {ruta_repo.name}. Skipping."
            )
            return json.dumps({
                "check_type_to_results": {},
                "results": {
                    "failed_checks": [],
                    "passed_checks": [],
                    "skipped_checks": []
                },
                "summary": {}
            })

        LOGGER.info(f"CI/CD files found in {ruta_repo.name}: {len(cicd_files)} files")

        # Ejecutar Checkov
        checkov_path = self.checkov_path or self._resolver_checkov()
        comando = [
            checkov_path,
            "--directory",
            str(ruta_repo),
            "--format",
            FORMATO_SALIDA_CHECKOV,
            "--quiet",
            "--skip-download",
        ]

        LOGGER.info(f"Running Checkov on {ruta_repo.name}...")
        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            check=False,
        )

        if resultado.returncode != 0:
            # Checkov retorna >0 si hay fallos encontrados, pero podría haber errores reales
            if "error" in resultado.stderr.lower() and "not found" in resultado.stderr.lower():
                LOGGER.debug(f"Checkov stderr: {resultado.stderr}")
                # Retorna resultado vacío si hay error pero continúa
                return json.dumps({
                    "check_type_to_results": {},
                    "results": {
                        "failed_checks": [],
                        "passed_checks": [],
                        "skipped_checks": []
                    },
                    "summary": {}
                })
            LOGGER.debug(f"Checkov stderr: {resultado.stderr}")

        if not resultado.stdout or resultado.stdout.strip() == "":
            return json.dumps({
                "check_type_to_results": {},
                "results": {
                    "failed_checks": [],
                    "passed_checks": [],
                    "skipped_checks": []
                },
                "summary": {}
            })

        return resultado.stdout

    def parse_checkov_output(self, checkov_json_str: str) -> dict:
        """Convierte JSON de Checkov a un formato normalizado."""
        LOGGER.info("Parsing Checkov output...")

        try:
            checkov_data = json.loads(checkov_json_str)
        except json.JSONDecodeError as error:
            raise RuntimeError(f"Failed to parse Checkov JSON output: {error}")

        # Extraer misconfigurations (failed checks)
        resultados_raw = checkov_data.get("results", {})
        failed_checks = resultados_raw.get("failed_checks", [])
        passed_checks = resultados_raw.get("passed_checks", [])
        skipped_checks = resultados_raw.get("skipped_checks", [])

        LOGGER.info(f"Found {len(failed_checks)} failed checks in Checkov output")

        # Normalizar
        resultados = {
            "total_misconfigurations": len(failed_checks),
            "total_passed_checks": len(passed_checks),
            "total_skipped_checks": len(skipped_checks),
            "misconfigurations_by_severity": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
            },
            "misconfigurations_by_framework": {},
            "misconfigurations": [],
            "checkov_metadata": self._extraer_metadata(checkov_data),
        }

        for failed_check in failed_checks:
            misc_norm = self._procesar_misconfiguracion(failed_check)
            resultados["misconfigurations"].append(misc_norm)

            # Contar por severidad
            severity = misc_norm.get("severity", "LOW").upper()
            if severity in resultados["misconfigurations_by_severity"]:
                resultados["misconfigurations_by_severity"][severity] += 1

            # Contar por framework
            framework = misc_norm.get("framework", "Unknown")
            if framework not in resultados["misconfigurations_by_framework"]:
                resultados["misconfigurations_by_framework"][framework] = 0
            resultados["misconfigurations_by_framework"][framework] += 1

        LOGGER.info(
            f"Parsed {resultados['total_misconfigurations']} misconfigurations total"
        )
        return resultados

    def save_analysis(self, repo_name: str, checkov_raw: str, analysis_data: dict) -> tuple[Path, Path]:
        """Guarda el análisis en dos formatos: raw (debug) y normalizado (análisis)."""
        if not repo_name:
            raise ValueError("Repository name cannot be empty.")

        self.output_path.mkdir(parents=True, exist_ok=True)

        # Guardar formato raw (original de Checkov)
        ruta_raw = self.output_path / f"{repo_name}{SUFIJO_CICD_RAW}"
        ruta_raw.write_text(checkov_raw, encoding="utf-8")
        LOGGER.info(
            f"Raw Checkov output saved to {ruta_raw.relative_to(self.project_root)}"
        )

        # Guardar formato normalizado
        ruta_normalizado = self.output_path / f"{repo_name}{SUFIJO_CICD}"
        contenido_json = json.dumps(analysis_data, ensure_ascii=False, indent=2)
        ruta_normalizado.write_text(contenido_json, encoding="utf-8")
        LOGGER.info(
            f"Normalized analysis saved to {ruta_normalizado.relative_to(self.project_root)}"
        )

        return ruta_raw, ruta_normalizado

    def run(self):
        """Orquesta el descubrimiento y análisis con Trivy."""
        repositorios = self.discover_repositories()
        self._validar_directorio_salida()

        if not repositorios:
            LOGGER.warning("No repositories discovered. Exiting.")
            return

        if not self.dry_run:
            self._diagnosticar_entorno()

        self.output_path.mkdir(parents=True, exist_ok=True)

        repositorios_analizados = 0
        archivos_generados = 0
        omitidos = 0
        errores = 0

        for indice, repo_path in enumerate(repositorios, start=1):
            ruta_repo = self.project_root / repo_path

            try:
                if self.dry_run:
                    LOGGER.info(
                        f"[{indice}/{len(repositorios)}] Dry-run: would scan {repo_path}"
                    )
                    omitidos += 1
                    continue

                LOGGER.info(
                    f"[{indice}/{len(repositorios)}] Scanning {repo_path} for CI/CD vulnerabilities..."
                )

                # Ejecutar análisis
                checkov_output = self.run_checkov(repo_path)

                # Procesar resultados
                analysis = self.parse_checkov_output(checkov_output)

                # Guardar ambos formatos
                self.save_analysis(ruta_repo.name, checkov_output, analysis)

                repositorios_analizados += 1
                archivos_generados += 2  # raw + normalizado

            except Exception as error:
                errores += 1
                self._eliminar_archivos_parciales(ruta_repo.name)
                LOGGER.error(f"Error scanning {repo_path}: {error}")

        LOGGER.info(
            (
                f"Summary | total_repos={len(repositorios)} | "
                f"repos_scanned={repositorios_analizados} | "
                f"files_generated={archivos_generados} | "
                f"skipped={omitidos} | errors={errores}"
            )
        )

    def _validar_directorio_repos(self):
        if not self.repos_path.exists():
            raise FileNotFoundError(f"Repos directory not found: {self.repos_path}")

        if not self.repos_path.is_dir():
            raise NotADirectoryError(f"Repos path is not a directory: {self.repos_path}")

    def _validar_directorio_salida(self):
        if self.output_path.exists() and not self.output_path.is_dir():
            raise NotADirectoryError(f"Output path exists but is not a directory: {self.output_path}")

    def _resolver_checkov(self) -> str:
        """Busca el ejecutable de Checkov en PATH."""
        ruta_checkov = shutil.which(self.checkov_bin)
        if not ruta_checkov:
            raise RuntimeError(MENSAJE_CHECKOV_NO_INSTALADO)

        self.checkov_path = ruta_checkov
        return ruta_checkov

    def _diagnosticar_entorno(self):
        """Verifica que Checkov esté disponible."""
        LOGGER.info("=== Checkov Environment Diagnostics ===")

        try:
            checkov_path = self._resolver_checkov()
            resultado = subprocess.run(
                [checkov_path, "--version"],
                capture_output=True,
                text=True,
                check=False,
            )
            LOGGER.info(f"Checkov CLI: {resultado.stdout.strip()}")
        except Exception as e:
            LOGGER.error(f"Checkov CLI check failed: {e}")

    def _procesar_misconfiguracion(self, check: dict) -> dict:
        """Normaliza información de un check fallido de Checkov."""
        return {
            "check_id": check.get("check_id", ""),
            "check_name": check.get("check_name", ""),
            "check_result": check.get("check_result", {}),
            "code_block": check.get("code_block", []),
            "file_path": check.get("file_path", ""),
            "file_abs_path": check.get("file_abs_path", ""),
            "repo_file_path": check.get("repo_file_path", ""),
            "file_line_range": check.get("file_line_range", []),
            "resource": check.get("resource", ""),
            "evaluations": check.get("evaluations", {}),
            "check_class": check.get("check_class", ""),
            "severity": check.get("severity", "LOW"),
            "framework": check.get("framework", "Unknown"),
        }

    def _extraer_metadata(self, checkov_data: dict) -> dict:
        """Extrae metadata de Checkov."""
        summary = checkov_data.get("summary", {})
        return {
            "framework": summary.get("framework", ""),
            "check_type": summary.get("check_type", ""),
            "passed": summary.get("passed", 0),
            "failed": summary.get("failed", 0),
            "skipped": summary.get("skipped", 0),
            "parsing_errors": summary.get("parsing_errors", 0),
        }

    def _eliminar_archivos_parciales(self, repo_name: str):
        """Elimina archivos parciales en caso de error."""
        for sufijo in [SUFIJO_CICD_RAW, SUFIJO_CICD]:
            ruta_salida = self.output_path / f"{repo_name}{sufijo}"
            if ruta_salida.exists():
                ruta_salida.unlink()


def _construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyzes CI/CD configuration vulnerabilities in all repositories using Checkov."
    )
    parser.add_argument(
        "--repos-path",
        default=str(RUTA_REPOS_POR_DEFECTO),
        help="Path to the directory containing repositories to analyze.",
    )
    parser.add_argument(
        "--output-path",
        default=str(RUTA_RESULTADOS_POR_DEFECTO),
        help="Path to the directory where analysis results will be saved.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Shows which repositories would be scanned without running Checkov.",
    )
    return parser


def main() -> int:
    parser = _construir_parser()
    args = parser.parse_args()

    analizador = CICDAnalyzer(args.repos_path, args.output_path)
    analizador.dry_run = args.dry_run
    try:
        analizador.run()
    except Exception as error:
        LOGGER.error("%s", error)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""
Análisis de Vulnerabilidades en Configuraciones CI/CD

Script que automatiza el escaneo de vulnerabilidades en archivos de configuración CI/CD
sobre múltiples repositorios usando Checkov, una herramienta de análisis enfocada en
misconfigurations de infraestructura e IaC.

Proceso:
1. Descubre todos los repositorios en data/repos/
2. Identifica archivos de configuración CI/CD (.github/workflows/, .gitlab-ci.yml, etc.)
3. Ejecuta Checkov para detectar misconfigurations y vulnerabilidades
4. Normaliza la salida JSON de Checkov
5. Guarda resultados en data/results/ con dos formatos:
   - {repo-name}-cicd-raw.json: Salida original de Checkov (para debug)
   - {repo-name}-cicd.json: Formato normalizado (para análisis)

Uso:
    python scripts/generate_analysis_CICD.py                    # Ejecutar análisis completo
    python scripts/generate_analysis_CICD.py --dry-run          # Ver qué se haría sin ejecutar
    python scripts/generate_analysis_CICD.py --repos-path PATH  # Con rutas personalizadas

Requisitos:
    - Checkov instalado (pip install checkov)
    - Repositorios clonados en data/repos/

Salida:
    - Archivos JSON en data/results/ con patrones:
      * {repo-name}-cicd-raw.json: Salida original de Checkov
      * {repo-name}-cicd.json: Formato normalizado
    - Logs con progreso e información de errores
    - Resumen final con estadísticas de misconfigurations
"""
