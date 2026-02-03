"""ML Model analyzer for TFLite, CoreML, and other formats."""

import hashlib
import logging
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from api.models.database import Finding, MLModel, MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)


class MLModelAnalyzer(BaseAnalyzer):
    """Analyzes ML models embedded in mobile applications."""

    name = "ml_model_analyzer"
    platform = "cross-platform"

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze ML models in an app."""
        findings: list[Finding] = []

        if not app.file_path:
            return findings

        try:
            # Extract ML models
            models = await self.extract_models(app)

            for model in models:
                # Analyze each model
                analysis = await self._analyze_model_file(model)
                findings.extend(await self._create_model_findings(app, model, analysis))

        except Exception as e:
            logger.error(f"ML model analysis failed: {e}")

        return findings

    async def extract_models(self, app: MobileApp) -> list[dict[str, Any]]:
        """Extract ML models from an app archive."""
        models: list[dict[str, Any]] = []

        model_extensions = {
            ".tflite": "tflite",
            ".mlmodel": "coreml",
            ".mlpackage": "coreml",
            ".onnx": "onnx",
            ".pt": "pytorch",
            ".ptl": "pytorch",
        }

        try:
            with zipfile.ZipFile(app.file_path, "r") as archive:
                for file_info in archive.filelist:
                    for ext, format_name in model_extensions.items():
                        if file_info.filename.lower().endswith(ext):
                            # Extract to temp directory
                            temp_dir = Path(tempfile.mkdtemp())
                            archive.extract(file_info.filename, temp_dir)
                            extracted_path = temp_dir / file_info.filename

                            # Calculate hash
                            content = archive.read(file_info.filename)
                            file_hash = hashlib.sha256(content).hexdigest()

                            models.append({
                                "name": Path(file_info.filename).name,
                                "format": format_name,
                                "file_path": str(extracted_path),
                                "original_path": file_info.filename,
                                "file_size": file_info.file_size,
                                "hash": file_hash,
                            })

        except Exception as e:
            logger.error(f"Failed to extract ML models: {e}")

        return models

    async def _analyze_model_file(self, model: dict[str, Any]) -> dict[str, Any]:
        """Analyze a single model file."""
        analysis: dict[str, Any] = {
            "input_tensors": [],
            "output_tensors": [],
            "operations": [],
            "labels": [],
            "vulnerabilities": [],
            "adversarial_risk": "unknown",
            "model_stealing_risk": "unknown",
        }

        format_name = model["format"]

        try:
            if format_name == "tflite":
                analysis = await self._analyze_tflite(model["file_path"])
            elif format_name == "coreml":
                analysis = await self._analyze_coreml(model["file_path"])
            elif format_name == "onnx":
                analysis = await self._analyze_onnx(model["file_path"])
        except Exception as e:
            logger.error(f"Model analysis failed: {e}")
            analysis["vulnerabilities"].append({
                "type": "analysis_error",
                "description": str(e),
            })

        return analysis

    async def _analyze_tflite(self, file_path: str) -> dict[str, Any]:
        """Analyze TensorFlow Lite model."""
        analysis: dict[str, Any] = {
            "input_tensors": [],
            "output_tensors": [],
            "operations": [],
            "labels": [],
            "vulnerabilities": [],
            "adversarial_risk": "medium",
            "model_stealing_risk": "high",
        }

        try:
            # Try to use TensorFlow Lite interpreter
            import tensorflow as tf

            interpreter = tf.lite.Interpreter(model_path=file_path)
            interpreter.allocate_tensors()

            # Get input details
            for tensor in interpreter.get_input_details():
                analysis["input_tensors"].append({
                    "name": tensor["name"],
                    "shape": list(tensor["shape"]),
                    "dtype": str(tensor["dtype"]),
                })

            # Get output details
            for tensor in interpreter.get_output_details():
                analysis["output_tensors"].append({
                    "name": tensor["name"],
                    "shape": list(tensor["shape"]),
                    "dtype": str(tensor["dtype"]),
                })

            # Check for vulnerabilities
            analysis["vulnerabilities"].append({
                "type": "model_extraction",
                "severity": "medium",
                "description": "TFLite models can be easily extracted and analyzed.",
            })

        except ImportError:
            logger.warning("TensorFlow not installed, using basic analysis")
            analysis = await self._basic_tflite_analysis(file_path)
        except Exception as e:
            logger.error(f"TFLite analysis failed: {e}")

        return analysis

    async def _basic_tflite_analysis(self, file_path: str) -> dict[str, Any]:
        """Basic TFLite analysis without TensorFlow."""
        analysis: dict[str, Any] = {
            "input_tensors": [],
            "output_tensors": [],
            "operations": [],
            "labels": [],
            "vulnerabilities": [],
            "adversarial_risk": "unknown",
            "model_stealing_risk": "high",
        }

        try:
            with open(file_path, "rb") as f:
                content = f.read()

            # Extract strings (potential labels)
            import re
            strings = re.findall(b'[\x20-\x7e]{4,}', content)
            potential_labels = [
                s.decode("utf-8", errors="ignore")
                for s in strings
                if len(s) < 100 and not any(c in s.decode("utf-8", errors="ignore") for c in ["()", "->", "::"])
            ]

            if potential_labels:
                analysis["labels"] = potential_labels[:50]

            analysis["vulnerabilities"].append({
                "type": "embedded_labels",
                "severity": "low",
                "description": f"Found {len(potential_labels)} potential labels in model.",
            })

        except Exception as e:
            logger.error(f"Basic TFLite analysis failed: {e}")

        return analysis

    async def _analyze_coreml(self, file_path: str) -> dict[str, Any]:
        """Analyze Core ML model."""
        analysis: dict[str, Any] = {
            "input_tensors": [],
            "output_tensors": [],
            "operations": [],
            "labels": [],
            "vulnerabilities": [],
            "adversarial_risk": "medium",
            "model_stealing_risk": "medium",
        }

        try:
            # CoreML analysis requires macOS
            import coremltools as ct

            model = ct.models.MLModel(file_path)

            # Get input/output specs
            for inp in model.input_description:
                analysis["input_tensors"].append({
                    "name": inp.name,
                    "type": str(inp.type),
                })

            for out in model.output_description:
                analysis["output_tensors"].append({
                    "name": out.name,
                    "type": str(out.type),
                })

        except ImportError:
            logger.warning("coremltools not installed (requires macOS)")
            analysis["vulnerabilities"].append({
                "type": "analysis_limited",
                "description": "CoreML analysis requires macOS with coremltools.",
            })
        except Exception as e:
            logger.error(f"CoreML analysis failed: {e}")

        return analysis

    async def _analyze_onnx(self, file_path: str) -> dict[str, Any]:
        """Analyze ONNX model."""
        analysis: dict[str, Any] = {
            "input_tensors": [],
            "output_tensors": [],
            "operations": [],
            "labels": [],
            "vulnerabilities": [],
            "adversarial_risk": "medium",
            "model_stealing_risk": "high",
        }

        try:
            import onnx

            model = onnx.load(file_path)

            # Get inputs
            for inp in model.graph.input:
                analysis["input_tensors"].append({
                    "name": inp.name,
                    "type": str(inp.type),
                })

            # Get outputs
            for out in model.graph.output:
                analysis["output_tensors"].append({
                    "name": out.name,
                    "type": str(out.type),
                })

            # Get operations
            op_types = set()
            for node in model.graph.node:
                op_types.add(node.op_type)

            analysis["operations"] = list(op_types)

        except ImportError:
            logger.warning("ONNX not installed")
        except Exception as e:
            logger.error(f"ONNX analysis failed: {e}")

        return analysis

    async def _create_model_findings(
        self,
        app: MobileApp,
        model: dict[str, Any],
        analysis: dict[str, Any],
    ) -> list[Finding]:
        """Create findings from model analysis."""
        findings: list[Finding] = []

        # Finding: Model detected
        findings.append(self.create_finding(
            app=app,
            title=f"ML Model Detected: {model['name']}",
            severity="info",
            category="ML Security",
            description=(
                f"Found {model['format'].upper()} model in the app.\n\n"
                f"File: {model['original_path']}\n"
                f"Size: {model['file_size']} bytes\n"
                f"Hash: {model['hash'][:16]}..."
            ),
            impact="ML models can reveal business logic and may be vulnerable to adversarial attacks.",
            remediation="Consider model obfuscation and server-side inference for sensitive models.",
            file_path=model["original_path"],
            owasp_masvs_category="MASVS-RESILIENCE",
        ))

        # Finding: Model stealing risk
        if analysis.get("model_stealing_risk") == "high":
            findings.append(self.create_finding(
                app=app,
                title=f"High Model Stealing Risk: {model['name']}",
                severity="medium",
                category="ML Security",
                description=(
                    "The ML model can be easily extracted and analyzed. "
                    "Model architecture, weights, and potentially training data "
                    "can be recovered."
                ),
                impact=(
                    "Attackers can clone the model, understand its decision boundaries, "
                    "and craft adversarial inputs."
                ),
                remediation=(
                    "Consider:\n"
                    "1. Server-side inference instead of on-device\n"
                    "2. Model encryption\n"
                    "3. Model watermarking\n"
                    "4. Quantization to reduce precision"
                ),
                file_path=model["original_path"],
                owasp_masvs_category="MASVS-RESILIENCE",
            ))

        # Finding: Labels exposed
        if analysis.get("labels"):
            findings.append(self.create_finding(
                app=app,
                title=f"ML Model Labels Exposed ({len(analysis['labels'])} labels)",
                severity="low",
                category="ML Security",
                description=(
                    f"Found {len(analysis['labels'])} labels embedded in the model. "
                    f"Sample labels:\n" +
                    "\n".join(f"- {l}" for l in analysis["labels"][:10])
                ),
                impact="Labels reveal the model's classification categories and business logic.",
                remediation="Consider encoding labels or storing them separately.",
                file_path=model["original_path"],
                owasp_masvs_category="MASVS-RESILIENCE",
            ))

        return findings

    async def analyze_model(self, model: MLModel) -> dict[str, Any]:
        """Analyze a model from the database."""
        model_info = {
            "format": model.model_format,
            "file_path": model.file_path,
            "name": model.model_name or "unknown",
        }
        return await self._analyze_model_file(model_info)
