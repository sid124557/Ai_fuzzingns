import os
from pathlib import Path
import json
import yaml
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
import hashlib

ROOT = Path("jitfuzz")

class Signal(str, Enum):
    NORMAL = "NORMAL"
    JS_EXCEPTION = "JS_EXCEPTION"
    ABORT = "ABORT"
    CRASH = "CRASH"
    HANG = "HANG"

class GrammarRuleType(str, Enum):
    STRUCTURAL = "structural"
    OPERATION = "operation"
    DECLARATION = "declaration"
    LITERAL = "literal"
    CONTROL_FLOW = "control_flow"

FILES = {
# ---------------- CONFIG ----------------
"config/grammar.dharma": r"""
// Baseline grammar with rule IDs for attribution
Program ::= Statement+ {program}
Statement ::= Expr ";" {statement} | VariableDecl ";" {vardecl}
VariableDecl ::= "var" Identifier "=" Expr {var_assign} | "let" Identifier "=" Expr {let_assign}
Expr ::= Literal {literal_expr} | BinaryExpr {binary_expr} | CallExpr {call_expr} | Identifier {ident_expr}
BinaryExpr ::= Expr "+" Expr {add_expr} | Expr "-" Expr {sub_expr} | Expr "*" Expr {mul_expr} | Expr "/" Expr {div_expr}
CallExpr ::= Identifier "(" ExprList ")" {call}
ExprList ::= Expr {single_arg} | Expr "," ExprList {multi_args}
Literal ::= Number {num_literal} | String {str_literal}
Number ::= [0-9]+ {integer}
String ::= "\"" [a-zA-Z]* "\"" {simple_string}
Identifier ::= [a-zA-Z_][a-zA-Z0-9_]* {identifier}
""",

"config/grammar_schema.yaml": r"""
version: "2.0.0"
rules:
  program:
    type: "structural"
    base_probability: 1.0
    risk_score: 0.0
  statement:
    type: "structural"
    base_probability: 0.5
    risk_score: 0.0
  vardecl:
    type: "statement"
    base_probability: 0.3
    risk_score: 0.1
  var_assign:
    type: "declaration"
    base_probability: 0.15
    risk_score: 0.05
  div_expr:
    type: "operation"
    base_probability: 0.1
    risk_score: 0.3
    comment: "Division can cause division by zero"
entropy_constraints:
  min_rule_probability: 0.01
  max_rule_probability: 0.95
  target_shannon_entropy: 2.5
""",

"config/v8_flags.json": r"""
{
  "common": [
    "--trace-deopt",
    "--trace-opt",
    "--allow-natives-syntax",
    "--logfile=%LOG%",
    "--log-all",
    "--predictable"
  ],
  "debug": [
    "--gc-interval=100",
    "--stack-size=1000",
    "--always-opt",
    "--max-opt-count=100"
  ],
  "asan": [
    "--enable-slow-asserts",
    "--verify-heap",
    "--abort-on-contradictory-flags"
  ]
}
""",

# ---------------- CORE ----------------
"core/config.py": r"""
from pydantic import BaseModel, Field, validator
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

class V8FlagsConfig(BaseModel):
    common: List[str] = Field(default_factory=list)
    debug: List[str] = Field(default_factory=list)
    asan: List[str] = Field(default_factory=list)
    
    @validator('*')
    def validate_flags(cls, v):
        return [f.strip() for f in v if f.strip()]

class GrammarRuleSchema(BaseModel):
    type: str
    base_probability: float = Field(ge=0.0, le=1.0)
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    max_depth: Optional[int] = Field(default=None, gt=0)
    
    class Config:
        extra = "allow"

class EntropyConstraints(BaseModel):
    min_rule_probability: float = Field(ge=0.001, le=0.1)
    max_rule_probability: float = Field(ge=0.5, le=1.0)
    target_shannon_entropy: float = Field(ge=1.0, le=4.0)

class GrammarSchema(BaseModel):
    version: str
    rules: Dict[str, GrammarRuleSchema]
    entropy_constraints: EntropyConstraints
    
    @validator('rules')
    def validate_rule_probabilities(cls, v):
        if not v:
            raise ValueError("At least one rule must be defined")
        return v

class JITFuzzConfig:
    def __init__(self, config_dir: Path = Path("config")):
        self.config_dir = Path(config_dir)
        self.grammar_schema: Optional[GrammarSchema] = None
        self.v8_flags: Optional[V8FlagsConfig] = None
        
    def load(self) -> None:
        self._load_grammar_schema()
        self._load_v8_flags()
        
    def _load_grammar_schema(self) -> None:
        path = self.config_dir / "grammar_schema.yaml"
        if not path.exists():
            raise FileNotFoundError(f"Grammar schema not found: {path}")
        
        with open(path) as f:
            data = yaml.safe_load(f)
            self.grammar_schema = GrammarSchema(**data)
    
    def _load_v8_flags(self) -> None:
        path = self.config_dir / "v8_flags.json"
        if not path.exists():
            raise FileNotFoundError(f"V8 flags not found: {path}")
        
        with open(path) as f:
            self.v8_flags = V8FlagsConfig(**json.load(f))
    
    def save_grammar_probs(self, probabilities: Dict[str, float], 
                          version: str = None) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        version = version or f"v{timestamp}"
        
        for rule_id, prob in probabilities.items():
            if rule_id in self.grammar_schema.rules:
                self.grammar_schema.rules[rule_id].base_probability = prob
        
        output_path = self.config_dir / f"grammar_schema.{version}.yaml"
        with open(output_path, "w") as f:
            yaml.dump(self.grammar_schema.dict(), f, indent=2)
        
        return output_path

class ConfigManager:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def initialize(self, config_dir: Path = Path("config")):
        if not self._initialized:
            self.config = JITFuzzConfig(config_dir)
            self.config.load()
            self._initialized = True
    
    @property
    def grammar(self) -> GrammarSchema:
        return self.config.grammar_schema
    
    @property
    def flags(self) -> V8FlagsConfig:
        return self.config.v8_flags
""",

"core/utils.py": r"""
import logging
import sys
from pathlib import Path
from datetime import datetime
import hashlib
import time

class TraceLogger:
    def __init__(self, log_dir: Path = Path("logs")):
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = log_dir / f"trace_{timestamp}.log"
        
        self.logger = logging.getLogger("jitfuzz")
        self.logger.setLevel(logging.DEBUG)
        
        # File handler
        fh = logging.FileHandler(self.log_file)
        fh.setLevel(logging.DEBUG)
        
        # Console handler
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(module)-15s | %(message)s',
            datefmt='%H:%M:%S'
        )
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)
    
    def debug(self, msg: str, **kwargs):
        self.logger.debug(msg + (f" | {kwargs}" if kwargs else ""))
    
    def info(self, msg: str, **kwargs):
        self.logger.info(msg + (f" | {kwargs}" if kwargs else ""))
    
    def warning(self, msg: str, **kwargs):
        self.logger.warning(msg + (f" | {kwargs}" if kwargs else ""))
    
    def error(self, msg: str, **kwargs):
        self.logger.error(msg + (f" | {kwargs}" if kwargs else ""))

_logger = TraceLogger()
debug = _logger.debug
info = _logger.info
warning = _logger.error
error = _logger.error

def compute_hash(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()[:16]

def timeit(func):
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        debug(f"{func.__name__} took {time.time() - start:.3f}s")
        return result
    return wrapper
""",

"core/artifact.py": r"""
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
from datetime import datetime
from core.utils import debug, compute_hash, timeit
from collections import Counter

class SignalLabel(str, Enum):
    NORMAL = "NORMAL"
    JS_EXCEPTION = "JS_EXCEPTION"
    ABORT = "ABORT"
    CRASH = "CRASH"
    HANG = "HANG"
    JIT_ASSUMPTION_VIOLATION = "JIT_ASSUMPTION_VIOLATION"
    MEMORY_CORRUPTION = "MEMORY_CORRUPTION"

@dataclass(frozen=True)
class SourceLocation:
    start_line: int
    start_column: int
    end_line: int
    end_column: int

@dataclass(frozen=True)
class RuleInstance:
    rule_id: str
    instance_id: str
    parent_instance: Optional[str]
    ast_node_ids: List[str] = field(default_factory=list)
    depth: int
    token_range: Tuple[int, int]
    expansion: str
    rule_type: GrammarRuleType
    location: Optional[SourceLocation] = None
    
    def to_graph_node(self) -> Dict[str, Any]:
        return {
            "node_id": f"RULE::{self.instance_id}",
            "type": "rule",
            "rule_id": self.rule_id,
            "rule_type": self.rule_type.value,
            "depth": self.depth,
            "expansion_length": len(self.expansion),
            "hash": compute_hash(self.expansion)[:8]
        }

@dataclass
class JITTelemetry:
    deopt_count: int = 0
    tier_transitions: int = 0
    compilation_count: int = 0
    deopt_reasons: List[str] = field(default_factory=list)
    optimized_function_count: int = 0
    bailout_count: int = 0
    
    @classmethod
    def from_stderr(cls, stderr: str) -> "JITTelemetry":
        lines = stderr.split('\\n')
        deopt_reasons = []
        deopt_count = 0
        
        for line in lines:
            if "deoptimizing" in line.lower():
                deopt_count += 1
                if "reason:" in line.lower():
                    reason = line.split("reason:")[-1].strip()
                    deopt_reasons.append(reason[:100])
        
        return cls(
            deopt_count=deopt_count,
            deopt_reasons=deopt_reasons,
            tier_transitions=lines.count("marking")
        )

@dataclass
class RuntimeResult:
    label: SignalLabel
    exit_code: int
    exec_time_ms: int
    stdout: str
    stderr: str
    jit_telemetry: JITTelemetry
    signal_strength: float = 1.0
    memory_used_mb: Optional[float] = None
    
    @property
    def is_unstable(self) -> bool:
        unstable_labels = {
            SignalLabel.CRASH, SignalLabel.ABORT, SignalLabel.HANG,
            SignalLabel.MEMORY_CORRUPTION, SignalLabel.JIT_ASSUMPTION_VIOLATION
        }
        return self.label in unstable_labels
    
    @property
    def severity_score(self) -> float:
        base_scores = {
            SignalLabel.MEMORY_CORRUPTION: 1.0,
            SignalLabel.CRASH: 0.9,
            SignalLabel.ABORT: 0.8,
            SignalLabel.HANG: 0.7,
            SignalLabel.JIT_ASSUMPTION_VIOLATION: 0.6,
            SignalLabel.JS_EXCEPTION: 0.3,
            SignalLabel.NORMAL: 0.0
        }
        
        base = base_scores.get(self.label, 0.5)
        deopt_multiplier = min(1.0 + (self.jit_telemetry.deopt_count * 0.05), 1.5)
        return min(base * self.signal_strength * deopt_multiplier, 1.0)

@dataclass
class ProgramArtifact:
    program_id: str
    seed: int
    source: str
    source_hash: str
    rule_trace: List[RuleInstance]
    runtime: RuntimeResult
    metadata: Dict[str, Any] = field(default_factory=dict)
    generation_time: datetime = field(default_factory=datetime.now)
    ast: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        if not self.source_hash:
            self.source_hash = compute_hash(self.source)
    
    @timeit
    def get_rule_frequency(self) -> Dict[str, int]:
        return Counter(rule.rule_id for rule in self.rule_trace)
    
    @timeit
    def get_rule_coverage(self) -> float:
        if not self.source:
            return 0.0
        
        coverage_mask = [False] * len(self.source)
        for rule in self.rule_trace:
            start, end = rule.token_range
            for i in range(max(0, start), min(end, len(self.source))):
                if i < len(coverage_mask):
                    coverage_mask[i] = True
        
        covered = sum(1 for i, ch in enumerate(self.source) 
                     if coverage_mask[i] and not ch.isspace())
        total = sum(1 for ch in self.source if not ch.isspace())
        return covered / max(total, 1)
    
    @timeit
    def get_critical_rules(self, top_k: int = 5) -> List[Tuple[str, float]]:
        if not self.runtime.is_unstable:
            return []
        
        rule_freq = self.get_rule_frequency()
        critical = []
        
        for rule_id, count in rule_freq.items():
            positions = [i for i, r in enumerate(self.rule_trace) if r.rule_id == rule_id]
            avg_position = sum(positions) / max(len(positions), 1)
            
            criticality = count * self.runtime.signal_strength * (1.0 + avg_position / len(self.rule_trace))
            critical.append((rule_id, criticality))
        
        critical.sort(key=lambda x: x[1], reverse=True)
        return critical[:top_k]
    
    def to_json(self) -> str:
        debug(f"Serializing artifact {self.program_id}")
        data = asdict(self)
        data['generation_time'] = self.generation_time.isoformat()
        data['runtime']['jit_telemetry'] = asdict(self.runtime.jit_telemetry)
        return json.dumps(data, indent=2)
    
    @classmethod
    def from_json(cls, json_str: str) -> "ProgramArtifact":
        data = json.loads(json_str)
        data['generation_time'] = datetime.fromisoformat(data['generation_time'])
        data['runtime']['jit_telemetry'] = JITTelemetry(**data['runtime']['jit_telemetry'])
        data['rule_trace'] = [RuleInstance(**r) for r in data['rule_trace']]
        data['runtime'] = RuntimeResult(**data['runtime'])
        return cls(**data)
""",

"core/generator.py": r"""
import subprocess
import tempfile
import json
from pathlib import Path
from typing import Tuple, List, Optional
from core.utils import debug, info, warning, error, timeit
from core.artifact import RuleInstance, GrammarRuleType

class DharmaGenerator:
    def __init__(self, grammar_path: Path, dharma_bin: str = "dharma", 
                 grammar_config_path: Optional[Path] = None):
        self.grammar_path = Path(grammar_path)
        self.dharma_bin = dharma_bin
        self.grammar_config = None
        
        if grammar_config_path:
            with open(grammar_config_path) as f:
                self.grammar_config = json.load(f)
        
        try:
            subprocess.run([dharma_bin, "--version"], 
                         capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            warning(f"Dharma binary {dharma_bin} not found")
    
    @timeit
    def generate(self, seed: int, max_depth: int = 10) -> Tuple[str, List[RuleInstance]]:
        debug(f"Generating with seed {seed}, max_depth={max_depth}")
        
        with tempfile.TemporaryDirectory() as tmp:
            js_path = Path(tmp) / "out.js"
            trace_path = Path(tmp) / "trace.json"
            
            cmd = [
                self.dharma_bin,
                "--grammar", str(self.grammar_path),
                "--seed", str(seed),
                "--max-depth", str(max_depth),
                "--emit-js", str(js_path),
                "--emit-trace", str(trace_path),
                "--format", "json"
            ]
            
            try:
                subprocess.check_call(cmd, stdout=subprocess.DEVNULL, 
                                    stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError as e:
                error(f"Dharma generation failed: {e}")
                raise
            
            source = js_path.read_text(encoding='utf-8')
            trace = self._parse_trace(trace_path, source)
            
            info(f"Generated {len(source)} chars, {len(trace)} rules")
            return source, trace
    
    def _parse_trace(self, trace_path: Path, source: str) -> List[RuleInstance]:
        try:
            with open(trace_path) as f:
                raw_trace = json.load(f)
        except json.JSONDecodeError as e:
            error(f"Failed to parse trace JSON: {e}")
            return []
        
        rule_instances = []
        
        for item in raw_trace:
            required = ['rule_id', 'instance_id', 'ast_node_id', 'token_start', 'token_end']
            if not all(field in item for field in required):
                warning(f"Skipping trace item missing fields: {item}")
                continue
            
            rule_type = GrammarRuleType.STRUCTURAL
            if self.grammar_config:
                rule_info = self.grammar_config['rules'].get(item['rule_id'], {})
                rule_type = GrammarRuleType(rule_info.get('type', 'structural'))
            
            token_start = item['token_start']
            token_end = min(item['token_end'], len(source))
            expansion = source[token_start:token_end]
            
            instance = RuleInstance(
                rule_id=item['rule_id'],
                instance_id=item['instance_id'],
                parent_instance=item.get('parent_instance'),
                ast_node_ids=[item['ast_node_id']],
                depth=item.get('depth', 0),
                token_range=(token_start, token_end),
                expansion=expansion,
                rule_type=rule_type
            )
            rule_instances.append(instance)
        
        rule_instances.sort(key=lambda x: x.depth)
        debug(f"Parsed {len(rule_instances)} rule instances")
        return rule_instances
    
    def validate_trace_coverage(self, source: str, trace: List[RuleInstance]) -> bool:
        if not trace:
            return False
        
        coverage = [False] * len(source)
        for rule in trace:
            start, end = rule.token_range
            for i in range(start, min(end, len(source))):
                if i < len(coverage):
                    coverage[i] = True
        
        uncovered = sum(1 for i, covered in enumerate(coverage) 
                       if not covered and not source[i].isspace())
        coverage_ratio = 1 - (uncovered / max(1, len(source)))
        debug(f"Trace coverage: {coverage_ratio:.2%}")
        
        return coverage_ratio > 0.95
""",

"core/signals.py": r"""
import re
from enum import Enum
from typing import Dict, Any
from core.utils import debug

class V8Signal(str, Enum):
    NORMAL = "NORMAL"
    JS_EXCEPTION = "JS_EXCEPTION"
    ABORT = "ABORT"
    CRASH = "CRASH"
    HANG = "HANG"
    JIT_ASSUMPTION_VIOLATION = "JIT_ASSUMPTION_VIOLATION"
    MEMORY_CORRUPTION = "MEMORY_CORRUPTION"

class SignalClassifier:
    JS_ERROR_PATTERNS = [
        (re.compile(r"SyntaxError"), "JS_EXCEPTION"),
        (re.compile(r"TypeError"), "JS_EXCEPTION"),
        (re.compile(r"ReferenceError"), "JS_EXCEPTION"),
        (re.compile(r"RangeError"), "JS_EXCEPTION"),
        (re.compile(r"MemoryError"), "MEMORY_CORRUPTION")
    ]
    
    V8_ABORT_PATTERNS = [
        (re.compile(r"CHECK failed"), "ABORT"),
        (re.compile(r"DCHECK failed"), "ABORT"),
        (re.compile(r"# Fatal error"), "ABORT"),
        (re.compile(r"#\s*Assertion failed"), "ABORT")
    ]
    
    JIT_SPECIFIC_PATTERNS = [
        (re.compile(r"deoptimization bailout"), "JIT_ASSUMPTION_VIOLATION"),
        (re.compile(r"wrong map"), "JIT_ASSUMPTION_VIOLATION"),
        (re.compile(r"not a Smi"), "JIT_ASSUMPTION_VIOLATION"),
        (re.compile(r"not a HeapNumber"), "JIT_ASSUMPTION_VIOLATION"),
        (re.compile(r"bailout reason"), "JIT_ASSUMPTION_VIOLATION")
    ]
    
    MEMORY_PATTERNS = [
        (re.compile(r"AddressSanitizer"), "MEMORY_CORRUPTION"),
        (re.compile(r"heap-bufferLiteral ::= Number {num_literal} | String {str_literal}
Number ::= [0-9]+ {integer}
String ::= "\"" [a-zA-Z]* "\"" {simple_string}
Identifier ::= [a-zA-Z_][a-zA-Z0-9_]* {identifier}
""",

"config/grammar_schema.json": r"""
{
  "version": "1.0.0",
  "rules": {
    "program": {"type": "structural", "base_probability": 1.0},
    "statement": {"type": "structural", "base_probability": 0.5},
    "vardecl": {"type": "statement", "base_probability": 0.3},
    "var_assign": {"type": "declaration", "base_probability": 0.15},
    "div_expr": {"type": "operation", "base_probability": 0.1, "risk_score": 0.0}
  },
  "entropy_constraints": {
    "min_rule_probability": 0.01,
    "max_rule_probability": 0.95,
    "target_shannon_entropy": 2.5
  }
}
""",

"config/v8_flags.json": r"""
{
  "common": [
    "--trace-deopt",
    "--trace-opt",
    "--allow-natives-syntax",
    "--logfile=%LOG%",
    "--log-all"
  ],
  "debug": [
    "--gc-interval=100",
    "--stack-size=1000"
  ],
  "asan": [
    "--enable-slow-asserts",
    "--verify-heap"
  ]
}
""",

# ---------------- CORE ----------------
"core/utils.py": r"""
import logging
import sys
from pathlib import Path
from datetime import datetime

class TraceLogger:
    def __init__(self, log_dir: Path = Path("logs")):
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = log_dir / f"trace_{timestamp}.log"
        
        self.logger = logging.getLogger("jitfuzz")
        self.logger.setLevel(logging.DEBUG)
        
        # File handler
        fh = logging.FileHandler(self.log_file)
        fh.setLevel(logging.DEBUG)
        
        # Console handler
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(module)-15s | %(message)s',
            datefmt='%H:%M:%S'
        )
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)
    
    def debug(self, msg: str, **kwargs):
        self.logger.debug(msg + (f" | {kwargs}" if kwargs else ""))
    
    def info(self, msg: str, **kwargs):
        self.logger.info(msg + (f" | {kwargs}" if kwargs else ""))
    
    def warning(self, msg: str, **kwargs):
        self.logger.warning(msg + (f" | {kwargs}" if kwargs else ""))
    
    def error(self, msg: str, **kwargs):
        self.logger.error(msg + (f" | {kwargs}" if kwargs else ""))

# Global logger instance
_logger = TraceLogger()
debug = _logger.debug
info = _logger.info
warning = _logger.warning
error = _logger.error

def compute_hash(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()[:16]

def timeit(func):
    import time
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        debug(f"{func.__name__} took {time.time() - start:.3f}s")
        return result
    return wrapper
""",

"core/artifact.py": r"""
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Tuple
import json
from datetime import datetime
from enum import Enum
from core.utils import debug, compute_hash

class GrammarRuleType(str, Enum):
    STRUCTURAL = "structural"
    OPERATION = "operation"
    DECLARATION = "declaration"
    LITERAL = "literal"
    CONTROL_FLOW = "control_flow"

@dataclass(frozen=True)
class RuleInstance:
    """Immutable representation of a grammar rule application"""
    rule_id: str
    instance_id: str
    parent_instance: Optional[str]
    ast_node_id: str  # Maps to specific AST node
    depth: int
    token_range: Tuple[int, int]  # (start, end) in source
    expansion: str  # The actual string produced by this rule
    rule_type: GrammarRuleType = field(default=GrammarRuleType.STRUCTURAL)
    
    def to_graph_node(self) -> Dict[str, Any]:
        return {
            "node_id": f"RULE::{self.instance_id}",
            "type": "rule",
            "rule_id": self.rule_id,
            "rule_type": self.rule_type.value,
            "depth": self.depth,
            "expansion": self.expansion[:50]  # Truncate for graph
        }

@dataclass(frozen=True)
class JITTelemetry:
    """JIT-specific runtime information"""
    deopt_count: int = 0
    tier_transitions: int = 0
    compilation_count: int = 0
    deopt_reasons: List[str] = field(default_factory=list)
    optimized_function_count: int = 0
    bailout_count: int = 0
    
    @classmethod
    def from_stderr(cls, stderr: str) -> "JITTelemetry":
        lines = stderr.split('\\n')
        deopt_reasons = []
        deopt_count = 0
        
        for line in lines:
            if "deoptimizing" in line.lower() or "deopt" in line.lower():
                deopt_count += 1
                # Extract reason if present
                if "reason:" in line.lower():
                    reason = line.split("reason:")[-1].strip()
                    deopt_reasons.append(reason[:100])  # Truncate
            
            # Count tier transitions (Ignition -> TurboFan etc)
            # This is simplified; real parsing would use V8's log format
        
        return cls(
            deopt_count=deopt_count,
            deopt_reasons=deopt_reasons,
            tier_transitions=lines.count("marking")  # Approximation
        )

@dataclass
class RuntimeResult:
    label: str
    exit_code: int
    exec_time_ms: int
    stdout: str
    stderr: str
    jit_telemetry: JITTelemetry
    signal_strength: float = 1.0  # How "strong" is this signal (0.0 to 1.0)
    
    @property
    def is_unstable(self) -> bool:
        return self.label not in ["NORMAL", "JS_EXCEPTION"]

@dataclass
class ProgramArtifact:
    program_id: str
    seed: int
    source: str
    source_hash: str
    rule_trace: List[RuleInstance]
    runtime: RuntimeResult
    metadata: Dict[str, Any] = field(default_factory=dict)
    generation_time: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        if not self.source_hash:
            self.source_hash = compute_hash(self.source)
    
    def to_json(self) -> str:
        debug(f"Serializing artifact {self.program_id}")
        
        # Convert dataclasses to dicts
        data = asdict(self)
        
        # Handle datetime serialization
        data['generation_time'] = self.generation_time.isoformat()
        
        # Convert JITTelemetry
        if isinstance(self.runtime.jit_telemetry, JITTelemetry):
            data['runtime']['jit_telemetry'] = asdict(self.runtime.jit_telemetry)
        
        return json.dumps(data, indent=2)
    
    @classmethod
    def from_json(cls, json_str: str) -> "ProgramArtifact":
        data = json.loads(json_str)
        
        # Restore datetime
        data['generation_time'] = datetime.fromisoformat(data['generation_time'])
        
        # Restore JITTelemetry
        if 'jit_telemetry' in data['runtime']:
            data['runtime']['jit_telemetry'] = JITTelemetry(**data['runtime']['jit_telemetry'])
        
        # Restore RuleInstances
        rule_instances = []
        for r in data['rule_trace']:
            r['token_range'] = tuple(r['token_range'])
            rule_instances.append(RuleInstance(**r))
        data['rule_trace'] = rule_instances
        
        data['runtime'] = RuntimeResult(**data['runtime'])
        
        return cls(**data)
    
    def get_rule_frequency(self) -> Dict[str, int]:
        """Count how many times each rule was used"""
        freq = {}
        for rule in self.rule_trace:
            freq[rule.rule_id] = freq.get(rule.rule_id, 0) + 1
        return freq
""",

"core/generator.py": r"""
import subprocess
import tempfile
import json
from pathlib import Path
from typing import Tuple, List
from core.utils import debug, info, timeit
from core.artifact import RuleInstance, GrammarRuleType

class DharmaGenerator:
    def __init__(self, grammar_path: Path, dharma_bin: str = "dharma", 
                 grammar_config_path: Optional[Path] = None):
        self.grammar_path = Path(grammar_path)
        self.dharma_bin = dharma_bin
        self.grammar_config = None
        
        if grammar_config_path:
            with open(grammar_config_path) as f:
                self.grammar_config = json.load(f)
        
        # Validate Dharma exists
        try:
            subprocess.run([dharma_bin, "--version"], 
                         capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            warning(f"Dharma binary {dharma_bin} not found or not working")
    
    @timeit
    def generate(self, seed: int, max_depth: int = 10) -> Tuple[str, List[RuleInstance]]:
        """Generate a program with given seed, return source and traced rules"""
        debug(f"Generating with seed {seed}, max_depth={max_depth}")
        
        with tempfile.TemporaryDirectory() as tmp:
            js_path = Path(tmp) / "out.js"
            trace_path = Path(tmp) / "trace.json"
            
            cmd = [
                self.dharma_bin,
                "--grammar", str(self.grammar_path),
                "--seed", str(seed),
                "--max-depth", str(max_depth),
                "--emit-js", str(js_path),
                "--emit-trace", str(trace_path),
                "--format", "json"
            ]
            
            try:
                subprocess.check_call(cmd, stdout=subprocess.DEVNULL, 
                                    stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError as e:
                error(f"Dharma generation failed: {e}")
                raise
            
            # Read generated source
            source = js_path.read_text(encoding='utf-8')
            
            # Parse and validate trace
            trace = self._parse_trace(trace_path, source)
            
            info(f"Generated program size: {len(source)} chars, {len(trace)} rule applications")
            return source, trace
    
    def _parse_trace(self, trace_path: Path, source: str) -> List[RuleInstance]:
        """Parse Dharma trace and convert to RuleInstance objects"""
        try:
            with open(trace_path) as f:
                raw_trace = json.load(f)
        except json.JSONDecodeError as e:
            error(f"Failed to parse trace JSON: {e}")
            return []
        
        rule_instances = []
        
        for item in raw_trace:
            # Validate required fields
            required = ['rule_id', 'instance_id', 'ast_node_id', 'token_start', 'token_end']
            if not all(field in item for field in required):
                warning(f"Skipping trace item missing required fields: {item}")
                continue
            
            # Determine rule type from configuration if available
            rule_type = GrammarRuleType.STRUCTURAL
            if self.grammar_config:
                rule_info = self.grammar_config['rules'].get(item['rule_id'], {})
                rule_type = GrammarRuleType(rule_info.get('type', 'structural'))
            
            # Extract the actual expansion from source
            token_start = item['token_start']
            token_end = min(item['token_end'], len(source))
            expansion = source[token_start:token_end]
            
            instance = RuleInstance(
                rule_id=item['rule_id'],
                instance_id=item['instance_id'],
                parent_instance=item.get('parent_instance'),
                ast_node_id=item['ast_node_id'],
                depth=item.get('depth', 0),
                token_range=(token_start, token_end),
                expansion=expansion,
                rule_type=rule_type
            )
            rule_instances.append(instance)
        
        # Sort by depth for hierarchical processing
        rule_instances.sort(key=lambda x: x.depth)
        
        debug(f"Parsed {len(rule_instances)} rule instances")
        return rule_instances
    
    def validate_trace_coverage(self, source: str, trace: List[RuleInstance]) -> bool:
        """Verify that trace covers entire source (no unattributed tokens)"""
        if not trace:
            return False
        
        # Create a coverage mask
        coverage = [False] * len(source)
        
        for rule in trace:
            start, end = rule.token_range
            for i in range(start, min(end, len(source))):
                if i < len(coverage):
                    coverage[i] = True
        
        # Check for significant uncovered portions (ignore whitespace)
        uncovered = 0
        for i, covered in enumerate(coverage):
            if not covered and not source[i].isspace():
                uncovered += 1
        
        coverage_ratio = 1 - (uncovered / max(1, len(source)))
        debug(f"Trace coverage: {coverage_ratio:.2%}")
        
        return coverage_ratio > 0.95
""",

"core/signals.py": r"""
import re
from enum import Enum
from typing import Dict, Any
from core.utils import debug

class V8Signal(str, Enum):
    NORMAL = "NORMAL"
    JS_EXCEPTION = "JS_EXCEPTION"
    ABORT = "ABORT"
    CRASH = "CRASH"
    HANG = "HANG"
    JIT_ASSUMPTION_VIOLATION = "JIT_ASSUMPTION_VIOLATION"
    MEMORY_CORRUPTION = "MEMORY_CORRUPTION"

class SignalClassifier:
    """Classify V8 runtime behavior with focus on JIT instability"""
    
    # Patterns for different signal types
    JS_ERROR_PATTERNS = [
        (re.compile(r"SyntaxError"), "JS_EXCEPTION"),
        (re.compile(r"TypeError"), "JS_EXCEPTION"),
        (re.compile(r"ReferenceError"), "JS_EXCEPTION"),
        (re.compile(r"RangeError"), "JS_EXCEPTION")
    ]
    
    V8_ABORT_PATTERNS = [
        (re.compile(r"CHECK failed"), "ABORT"),
        (re.compile(r"DCHECK failed"), "ABORT"),
        (re.compile(r"# Fatal error"), "ABORT"),
        (re.compile(r"#\s*Assertion failed"), "ABORT")
    ]
    
    JIT_SPECIFIC_PATTERNS = [
        (re.compile(r"deoptimization bailout"), "JIT_ASSUMPTION_VIOLATION"),
        (re.compile(r"wrong map"), "JIT_ASSUMPTION_VIOLATION"),
        (re.compile(r"not a Smi"), "JIT_ASSUMPTION_VIOLATION"),
        (re.compile(r"not a HeapNumber"), "JIT_ASSUMPTION_VIOLATION")
    ]
    
    MEMORY_PATTERNS = [
        (re.compile(r"AddressSanitizer"), "MEMORY_CORRUPTION"),
        (re.compile(r"heap-buffer-overflow"), "MEMORY_CORRUPTION"),
        (re.compile(r"SEGV|segmentation fault", re.I), "CRASH"),
        (re.compile(r"SIGSEGV|SIGBUS|SIGILL"), "CRASH")
    ]
    
    def __init__(self):
        self.signal_strength_cache = {}
    
    def classify(self, exit_code: int, stdout: str, stderr: str) -> Dict[str, Any]:
        """
        Classify runtime behavior with signal strength.
        Returns dict with 'label' and 'signal_strength'.
        """
        combined = stdout + "\n" + stderr
        
        # Check for hangs (timeout handled by executor)
        
        # Check for memory corruption signals first (most severe)
        for pattern, label in self.MEMORY_PATTERNS:
            if pattern.search(combined):
                debug(f"Detected {label} via pattern: {pattern.pattern[:30]}...")
                return {
                    "label": label,
                    "signal_strength": 1.0,
                    "pattern_matched": pattern.pattern[:50]
                }
        
        # Check for V8 internal assertions
        for pattern, label in self.V8_ABORT_PATTERNS:
            if pattern.search(combined):
                debug(f"Detected {label} via pattern: {pattern.pattern[:30]}...")
                return {
                    "label": label,
                    "signal_strength": 0.9,
                    "pattern_matched": pattern.pattern[:50]
                }
        
        # Check for JIT-specific issues
        jit_issues = []
        for pattern, label in self.JIT_SPECIFIC_PATTERNS:
            matches = pattern.findall(combined)
            if matches:
                jit_issues.append((label, len(matches)))
        
        if jit_issues:
            # Use the most frequent JIT issue
            jit_issues.sort(key=lambda x: x[1], reverse=True)
            label, count = jit_issues[0]
            strength = min(0.8 + (count * 0.05), 0.95)
            debug(f"Detected {label} with {count} occurrences")
            return {
                "label": label,
                "signal_strength": strength,
                "occurrence_count": count
            }
        
        # Check for JavaScript exceptions
        for pattern, label in self.JS_ERROR_PATTERNS:
            if pattern.search(combined):
                debug(f"Detected {label} via pattern: {pattern.pattern[:30]}...")
                return {
                    "label": label,
                    "signal_strength": 0.3,  # Lower strength for JS exceptions
                    "pattern_matched": pattern.pattern[:50]
                }
        
        # Normal exit
        if exit_code == 0:
            return {
                "label": "NORMAL",
                "signal_strength": 0.1,  # Normal programs have minimal signal
                "note": "clean_exit"
            }
        
        # Unknown non-zero exit
        debug(f"Unknown exit code {exit_code}, classifying as CRASH")
        return {
            "label": "CRASH",
            "signal_strength": 0.7,
            "note": "unknown_non_zero_exit"
        }
    
    def calculate_signal_density(self, stderr: str) -> float:
        """
        Calculate signal density in stderr (proportion of interesting lines).
        Higher density suggests more concentrated issues.
        """
        lines = stderr.strip().split('\\n')
        if not lines:
            return 0.0
        
        interesting = 0
        interesting_keywords = ['error', 'fail', 'abort', 'deopt', 'bailout', 'check']
        
        for line in lines:
            line_lower = line.lower()
            if any(keyword in line_lower for keyword in interesting_keywords):
                interesting += 1
        
        return interesting / len(lines)
""",

"core/jit_parser.py": r"""
import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from core.utils import debug

@dataclass
class DeoptimizationEvent:
    """Structured representation of a deoptimization event"""
    function_name: str
    bailout_type: str
    reason: str
    bytecode_offset: Optional[int] = None
    deopt_id: Optional[int] = None
    
    @property
    def is_soft(self) -> bool:
        return "soft" in self.bailout_type.lower() or "eager" in self.bailout_type.lower()
    
    @property
    def is_hard(self) -> bool:
        return not self.is_soft

class JITTelemetryParser:
    """Parse V8 JIT telemetry from logs"""
    
    # Patterns for V8 log parsing (simplified)
    DEOPT_PATTERN = re.compile(
        r"\[deoptimizing\s*\(([^)]+)\):\s*"
        r"([^,]+),\s*"
        r"reason\s*=\s*([^,]+),"
        r".*?deopt_id\s*=\s*(\d+)"
    )
    
    TIER_TRANSITION_PATTERN = re.compile(
        r"\[marking\s+([^\s]+)\s+for\s+"
        r"(optimization|recompilation)"
    )
    
    COMPILE_PATTERN = re.compile(
        r"\[compiling\s+method\s+([^\s]+)"
    )
    
    def __init__(self):
        self.deopt_events: List[DeoptimizationEvent] = []
        self.tier_transitions: List[Dict[str, str]] = []
    
    def parse_log_file(self, log_path: str) -> Dict[str, Any]:
        """Parse a V8 log file for JIT telemetry"""
        try:
            with open(log_path, 'r') as f:
                content = f.read()
            return self.parse(content)
        except FileNotFoundError:
            debug(f"Log file not found: {log_path}")
            return self.get_empty_telemetry()
    
    def parse(self, log_content: str) -> Dict[str, Any]:
        """Parse log content string"""
        self.deopt_events.clear()
        self.tier_transitions.clear()
        
        lines = log_content.split('\\n')
        
        for line in lines:
            self._parse_deopt_line(line)
            self._parse_tier_transition(line)
        
        # Calculate summary statistics
        soft_deopts = sum(1 for e in self.deopt_events if e.is_soft)
        hard_deopts = sum(1 for e in self.deopt_events if e.is_hard)
        
        # Group deopt reasons
        reason_counts = {}
        for event in self.deopt_events:
            reason_counts[event.reason] = reason_counts.get(event.reason, 0) + 1
        
        return {
            "deopt_count": len(self.deopt_events),
            "soft_deopt_count": soft_deopts,
            "hard_deopt_count": hard_deopts,
            "tier_transition_count": len(self.tier_transitions),
            "deopt_reasons": [{"reason": r, "count": c} 
                            for r, c in reason_counts.items()],
            "deopt_events": [self._event_to_dict(e) for e in self.deopt_events],
            "unique_functions_deopted": len(set(e.function_name 
                                              for e in self.deopt_events))
        }
    
    def _parse_deopt_line(self, line: str) -> Optional[DeoptimizationEvent]:
        """Parse a single line for deoptimization info"""
        match = self.DEOPT_PATTERN.search(line)
        if match:
            bailout_type = match.group(1)
            function_name = match.group(2)
            reason = match.group(3)
            deopt_id = int(match.group(4)) if match.group(4) else None
            
            event = DeoptimizationEvent(
                function_name=function_name,
                bailout_type=bailout_type,
                reason=reason,
                deopt_id=deopt_id
            )
            self.deopt_events.append(event)
            return event
        return None
    
    def _parse_tier_transition(self, line: str) -> Optional[Dict[str, str]]:
        """Parse tier transition line"""
        match = self.TIER_TRANSITION_PATTERN.search(line)
        if match:
            function_name = match.group(1)
            action = match.group(2)
            transition = {
                "function": function_name,
                "action": action,
                "timestamp": len(self.tier_transitions)  # Simplified
            }
            self.tier_transitions.append(transition)
            return transition
        return None
    
    def _event_to_dict(self, event: DeoptimizationEvent) -> Dict[str, Any]:
        return {
            "function_name": event.function_name,
            "bailout_type": event.bailout_type,
            "reason": event.reason,
            "is_soft": event.is_soft,
            "deopt_id": event.deopt_id
        }
    
    def get_empty_telemetry(self) -> Dict[str, Any]:
        """Return empty telemetry dict"""
        return {
            "deopt_count": 0,
            "soft_deopt_count": 0,
            "hard_deopt_count": 0,
            "tier_transition_count": 0,
            "deopt_reasons": [],
            "deopt_events": [],
            "unique_functions_deopted": 0
        }
    
    def analyze_deopt_correlation(self, events: List[DeoptimizationEvent], 
                                 rule_patterns: Dict[str, List[str]]) -> Dict[str, float]:
        """
        Attempt to correlate deopt reasons with grammar rule patterns.
        Returns dict of rule_id -> correlation_score.
        """
        correlations = {}
        
        for rule_id, patterns in rule_patterns.items():
            match_count = 0
            for event in events:
                # Check if any pattern matches the deopt reason
                for pattern in patterns:
                    if pattern.lower() in event.reason.lower():
                        match_count += 1
                        break
            
            if events:
                correlations[rule_id] = match_count / len(events)
        
        return correlations
""",

"core/graph.py": r"""
import networkx as nx
import json
from typing import Dict, List, Any, Tuple, Optional
from enum import IntEnum
from core.utils import debug, timeit
from core.artifact import ProgramArtifact

class NodeType(IntEnum):
    AST = 0
    RULE = 1
    META = 2
    ATTRIBUTION = 3  # Explicit link edge type

class ProgramGraphBuilder:
    """Build attributed program graphs with rule-AST links"""
    
    def __init__(self, anonymize_rule_ids: bool = False):
        """
        Args:
            anonymize_rule_ids: If True, replace rule IDs with hashed versions
                              to prevent GNN from learning rule identity directly
        """
        self.anonymize = anonymize_rule_ids
        self.next_anon_id = 0
        self.anon_map = {}
    
    @timeit
    def build(self, artifact: ProgramArtifact) -> nx.DiGraph:
        """
        Build a directed graph with:
        - AST nodes (from parsing)
        - Rule nodes (from trace)
        - Attribution edges (rule -> AST)
        - Structural edges (AST parent/child)
        """
        G = nx.DiGraph()
        
        # Add metadata node
        meta_id = "META"
        G.add_node(meta_id, 
                  node_type=NodeType.META,
                  program_id=artifact.program_id,
                  signal_label=artifact.runtime.label,
                  signal_strength=artifact.runtime.signal_strength)
        
        # Parse AST (simplified - in reality use proper parser)
        ast_nodes = self._parse_simple_ast(artifact.source)
        
        # Add AST nodes
        for node_id, node_data in ast_nodes.items():
            G.add_node(node_id, **node_data, node_type=NodeType.AST)
        
        # Add AST structural edges
        for node_id, node_data in ast_nodes.items():
            if 'parent' in node_data and node_data['parent']:
                G.add_edge(node_data['parent'], node_id, 
                          edge_type='structural')
        
        # Add rule nodes and attribution edges
        rule_to_ast_map = self._build_rule_ast_map(artifact.rule_trace, ast_nodes)
        
        for rule_instance in artifact.rule_trace:
            rule_node_id = self._get_rule_node_id(rule_instance)
            
            # Add rule node
            G.add_node(rule_node_id,
                      node_type=NodeType.RULE,
                      rule_id=rule_instance.rule_id,
                      rule_type=rule_instance.rule_type.value,
                      depth=rule_instance.depth,
                      expansion_hash=hash(rule_instance.expansion) % 1000)
            
            # Link rule to meta
            G.add_edge(meta_id, rule_node_id, edge_type='rule_meta')
            
            # Add attribution edges from rule to AST nodes it generated
            if rule_node_id in rule_to_ast_map:
                for ast_node_id in rule_to_ast_map[rule_node_id]:
                    if ast_node_id in G:
                        G.add_edge(rule_node_id, ast_node_id, 
                                  edge_type='attribution',
                                  weight=1.0)
        
        # Add graph-level features
        G.graph.update({
            'num_ast_nodes': sum(1 for _, d in G.nodes(data=True) 
                               if d.get('node_type') == NodeType.AST),
            'num_rule_nodes': sum(1 for _, d in G.nodes(data=True) 
                                if d.get('node_type') == NodeType.RULE),
            'program_size': len(artifact.source),
            'rule_variety': len(set(d.get('rule_id', '') for _, d in G.nodes(data=True) 
                                  if d.get('node_type') == NodeType.RULE))
        })
        
        debug(f"Built graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
        return G
    
    def _get_rule_node_id(self, rule_instance) -> str:
        """Get node ID for rule, optionally anonymized"""
        if self.anonymize:
            if rule_instance.rule_id not in self.anon_map:
                self.anon_map[rule_instance.rule_id] = f"RULE_ANON_{self.next_anon_id}"
                self.next_anon_id += 1
            return self.anon_map[rule_instance.rule_id]
        return f"RULE::{rule_instance.instance_id}"
    
    def _parse_simple_ast(self, source: str) -> Dict[str, Dict[str, Any]]:
        """
        Simplified AST parser. In production, replace with Esprima-based parser.
        Returns dict: node_id -> node_data
        """
        # This is a placeholder - real implementation would use Esprima
        nodes = {}
        
        # Add a root node
        nodes['AST_ROOT'] = {
            'ast_type': 'Program',
            'text': source[:50] + '...' if len(source) > 50 else source,
            'parent': None
        }
        
        # Simplified: create nodes for major constructs
        lines = source.split(';')
        for i, line in enumerate(lines):
            if line.strip():
                node_id = f"AST_STMT_{i}"
                nodes[node_id] = {
                    'ast_type': 'Statement',
                    'text': line.strip()[:30],
                    'parent': 'AST_ROOT'
                }
        
        return nodes
    
    def _build_rule_ast_map(self, rule_trace: List, ast_nodes: Dict) -> Dict[str, List[str]]:
        """
        Map rule instances to AST nodes based on token ranges.
        This is simplified; real implementation needs proper AST parsing.
        """
        rule_map = {}
        
        for rule in rule_trace:
            rule_id = self._get_rule_node_id(rule)
            rule_map[rule_id] = []
            
            # Find AST nodes within rule's token range
            start, end = rule.token_range
            for ast_id, ast_data in ast_nodes.items():
                # Simplified: check if node text is within range
                node_text = ast_data.get('text', '')
                if node_text and len(node_text) > 0:
                    # This is a heuristic - real implementation would use
                    # proper AST node positions
                    rule_map[rule_id].append(ast_id)
        
        return rule_map
    
    def to_pyg_data(self, graph: nx.DiGraph):
        """Convert NetworkX graph to PyTorch Geometric Data object"""
        try:
            import torch
            from torch_geometric.data import Data
            
            # Extract node features
            node_features = []
            node_type_map = {'AST': 0, 'RULE': 1, 'META': 2}
            
            for node_id, data in graph.nodes(data=True):
                features = []
                
                # Node type feature
                node_type = data.get('node_type', NodeType.AST)
                features.append(node_type)
                
                # Rule type feature (if rule node)
                if node_type == NodeType.RULE:
                    rule_type = data.get('rule_type', 'structural')
                    type_encoding = {'structural': 0, 'operation': 1, 
                                   'declaration': 2, 'literal': 3, 
                                   'control_flow': 4}.get(rule_type, 5)
                    features.append(type_encoding)
                    features.append(data.get('depth', 0) / 10.0)  # Normalized depth
                else:
                    features.extend([0, 0])  # Padding for non-rule nodes
                
                node_features.append(features)
            
            # Edge indices and attributes
            edge_indices = []
            edge_attrs = []
            
            for u, v, data in graph.edges(data=True):
                edge_indices.append([list(graph.nodes()).index(u), 
                                   list(graph.nodes()).index(v)])
                edge_type = data.get('edge_type', 'structural')
                type_encoding = {'structural': 0, 'rule_meta': 1, 
                               'attribution': 2}.get(edge_type, 3)
                edge_attrs.append([type_encoding])
            
            x = torch.tensor(node_features, dtype=torch.float)
            edge_index = torch.tensor(edge_indices, dtype=torch.long).t().contiguous()
            edge_attr = torch.tensor(edge_attrs, dtype=torch.float)
            
            # Graph-level label (signal strength)
            y = torch.tensor([graph.graph.get('signal_strength', 0.0)], 
                           dtype=torch.float)
            
            return Data(x=x, edge_index=edge_index, edge_attr=edge_attr, y=y)
            
        except ImportError:
            debug("PyTorch Geometric not available, returning NetworkX graph")
            return graph
    
    def validate_graph(self, graph: nx.DiGraph) -> Tuple[bool, List[str]]:
        """Validate graph structure meets requirements"""
        issues = []
        
        # Check node types exist
        node_types = [d.get('node_type') for _, d in graph.nodes(data=True)]
        if NodeType.AST not in node_types:
            issues.append("No AST nodes in graph")
        if NodeType.RULE not in node_types:
            issues.append("No RULE nodes in graph")
        
        # Check attribution edges exist
        attribution_edges = [(u, v) for u, v, d in graph.edges(data=True)
                           if d.get('edge_type') == 'attribution']
        if not attribution_edges:
            issues.append("No attribution edges (rule->AST)")
        
        # Check graph is connected (weakly)
        if not nx.is_weakly_connected(graph):
            issues.append("Graph is not weakly connected")
        
        # Check for orphaned nodes (except META)
        orphans = [n for n in graph.nodes() 
                  if graph.degree(n) == 0 and n != "META"]
        if orphans:
            issues.append(f"Orphaned nodes: {len(orphans)}")
        
        return len(issues) == 0, issues
""",

"core/evolution.py": r"""
import json
import random
import math
from collections import defaultdict, Counter
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass, field
from core.utils import debug, info, warning
from core.artifact import ProgramArtifact, GrammarRuleType

@dataclass
class RuleStatistics:
    """Accumulated statistics for a grammar rule"""
    rule_id: str
    rule_type: GrammarRuleType
    total_occurrences: int = 0
    program_count: int = 0
    signal_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    avg_deopt_count: float = 0.0
    avg_signal_strength: float = 0.0
    deviation_scores: List[float] = field(default_factory=list)
    
    @property
    def signal_distribution(self) -> Dict[str, float]:
        if self.total_occurrences == 0:
            return {}
        return {sig: count / self.total_occurrences 
                for sig, count in self.signal_counts.items()}
    
    @property
    def instability_score(self) -> float:
        """Compute rule instability score (0.0 to 1.0)"""
        if self.total_occurrences < 3:  # Not enough data
            return 0.0
        
        # Weighted combination of signals
        weights = {
            'CRASH': 1.0,
            'ABORT': 0.8,
            'JIT_ASSUMPTION_VIOLATION': 0.7,
            'MEMORY_CORRUPTION': 1.0,
            'JS_EXCEPTION': 0.3,
            'NORMAL': 0.0
        }
        
        score = 0.0
        total_weight = 0.0
        
        for signal, count in self.signal_counts.items():
            weight = weights.get(signal, 0.5)
            proportion = count / self.total_occurrences
            score += weight * proportion
            total_weight += weight
        
        return score / total_weight if total_weight > 0 else 0.0
    
    @property
    def confidence(self) -> float:
        """Statistical confidence in the rule's metrics"""
        return min(1.0, math.log(self.total_occurrences + 1) / math.log(100))

class DiversityPreserver:
    """Maintain grammar diversity to prevent collapse"""
    
    def __init__(self, min_rule_prob: float = 0.01, 
                 max_rule_prob: float = 0.95,
                 target_entropy: float = 2.5):
        self.min_prob = min_rule_prob
        self.max_prob = max_rule_prob
        self.target_entropy = target_entropy
        self.rule_history: Dict[str, List[float]] = defaultdict(list)
    
    def compute_grammar_entropy(self, rule_probs: Dict[str, float]) -> float:
        """Compute Shannon entropy of the grammar distribution"""
        total = sum(rule_probs.values())
        if total == 0:
            return 0.0
        
        entropy = 0.0
        for prob in rule_probs.values():
            p = prob / total
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def adjust_for_diversity(self, rule_probs: Dict[str, float], 
                           rule_stats: Dict[str, RuleStatistics]) -> Dict[str, float]:
        """Adjust probabilities to maintain diversity"""
        adjusted = rule_probs.copy()
        
        # Ensure min probability for all rules
        for rule_id in adjusted:
            adjusted[rule_id] = max(self.min_prob, adjusted[rule_id])
        
        # Cap max probability
        for rule_id in adjusted:
            adjusted[rule_id] = min(self.max_prob, adjusted[rule_id])
        
        # Boost low-frequency rules
        entropy = self.compute_grammar_entropy(adjusted)
        if entropy < self.target_entropy:
            # Increase probability of least used rules
            low_freq_rules = [r for r, s in rule_stats.items() 
                            if s.total_occurrences < 10]
            if low_freq_rules:
                boost_amount = (self.target_entropy - entropy) * 0.1
                for rule_id in low_freq_rules:
                    if rule_id in adjusted:
                        adjusted[rule_id] = min(
                            self.max_prob,
                            adjusted[rule_id] + boost_amount
                        )
        
        # Normalize
        total = sum(adjusted.values())
        if total > 0:
            adjusted = {k: v / total for k, v in adjusted.items()}
        
        # Track history for stability
        for rule_id, prob in adjusted.items():
            self.rule_history[rule_id].append(prob)
            # Keep only last 100 entries
            if len(self.rule_history[rule_id]) > 100:
                self.rule_history[rule_id].pop(0)
        
        debug(f"Grammar entropy: {entropy:.3f} -> {self.compute_grammar_entropy(adjusted):.3f}")
        return adjusted
    
    def is_stable(self, rule_id: str, window: int = 20) -> bool:
        """Check if a rule's probability has stabilized"""
        history = self.rule_history.get(rule_id, [])
        if len(history) < window:
            return False
        
        recent = history[-window:]
        variance = max(recent) - min(recent)
        return variance < 0.05  # Stable if variation < 5%

class GrammarEvolutionController:
    """Conservative, explainable grammar evolution"""
    
    def __init__(self, grammar_config_path: Path):
        with open(grammar_config_path) as f:
            self.config = json.load(f)
        
        self.rule_stats: Dict[str, RuleStatistics] = {}
        self.diversity_preserver = DiversityPreserver(
            min_rule_prob=self.config['entropy_constraints']['min_rule_probability'],
            max_rule_prob=self.config['entropy_constraints']['max_rule_probability'],
            target_entropy=self.config['entropy_constraints']['target_shannon_entropy']
        )
        
        # Initialize rule statistics from config
        for rule_id, rule_info in self.config['rules'].items():
            self.rule_stats[rule_id] = RuleStatistics(
                rule_id=rule_id,
                rule_type=GrammarRuleType(rule_info.get('type', 'structural'))
            )
    
    def update_statistics(self, artifacts: List[ProgramArtifact]) -> None:
        """Update rule statistics from new artifacts"""
        for artifact in artifacts:
            rule_freq = artifact.get_rule_frequency()
            
            for rule_id, count in rule_freq.items():
                if rule_id not in self.rule_stats:
                    # New rule discovered
                    self.rule_stats[rule_id] = RuleStatistics(
                        rule_id=rule_id,
                        rule_type=GrammarRuleType.STRUCTURAL
                    )
                
                stats = self.rule_stats[rule_id]
                stats.total_occurrences += count
                stats.program_count += 1
                
                # Record signal
                signal = artifact.runtime.label
                stats.signal_counts[signal] += count
                
                # Update averages (incremental)
                if artifact.runtime.jit_telemetry:
                    old_avg = stats.avg_deopt_count
                    total_progs = stats.program_count
                    new_deopt = artifact.runtime.jit_telemetry.deopt_count
                    stats.avg_deopt_count = (
                        (old_avg * (total_progs - 1) + new_deopt) / total_progs
                    )
        
        debug(f"Updated stats for {len(self.rule_stats)} rules")
    
    def identify_candidate_rules(self, 
                               min_occurrences: int = 5,
                               top_k: int = 5) -> List[Tuple[str, float]]:
        """Identify rules with highest instability scores"""
        candidates = []
        
        for rule_id, stats in self.rule_stats.items():
            if stats.total_occurrences >= min_occurrences:
                score = stats.instability_score * stats.confidence
                candidates.append((rule_id, score))
        
        # Sort by score descending
        candidates.sort(key=lambda x: x[1], reverse=True)
        
        # Return top K with significant scores
        significant = [(r, s) for r, s in candidates[:top_k] if s > 0.1]
        
        info(f"Found {len(significant)} candidate rules for evolution")
        return significant
    
    def generate_evolution_report(self) -> Dict[str, Any]:
        """Generate structured report for LLM analysis"""
        candidates = self.identify_candidate_rules()
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "total_rules_tracked": len(self.rule_stats),
            "candidate_rules": [],
            "grammar_health": {
                "entropy": self.diversity_preserver.compute_grammar_entropy(
                    {r: s.total_occurrences for r, s in self.rule_stats.items()}
                ),
                "rule_coverage": len([s for s in self.rule_stats.values() 
                                    if s.total_occurrences > 0]),
                "avg_confidence": sum(s.confidence for s in self.rule_stats.values()) 
                                / max(1, len(self.rule_stats))
            }
        }
        
        for rule_id, score in candidates:
            stats = self.rule_stats[rule_id]
            report["candidate_rules"].append({
                "rule_id": rule_id,
                "rule_type": stats.rule_type.value,
                "instability_score": stats.instability_score,
                "confidence": stats.confidence,
                "total_occurrences": stats.total_occurrences,
                "signal_distribution": stats.signal_distribution,
                "avg_deopt_count": stats.avg_deopt_count
            })
        
        return report
    
    def apply_llm_suggestion(self, suggestion: Dict[str, Any]) -> bool:
        """
        Apply LLM suggestion if it passes validation.
        Returns True if applied, False if rejected.
        """
        required_fields = ['rule_id', 'action', 'rationale']
        if not all(field in suggestion for field in required_fields):
            warning(f"LLM suggestion missing required fields: {suggestion}")
            return False
        
        rule_id = suggestion['rule_id']
        action = suggestion['action']
        
        # Validate rule exists and has sufficient data
        if rule_id not in self.rule_stats:
            warning(f"LLM suggested unknown rule: {rule_id}")
            return False
        
        stats = self.rule_stats[rule_id]
        if stats.confidence < 0.3:  # Low confidence
            warning(f"Rule {rule_id} has low confidence ({stats.confidence:.2f})")
            return False
        
        # Action-specific validation
        if action == "split_rule":
            return self._validate_split_suggestion(suggestion, stats)
        elif action == "adjust_probability":
            return self._validate_probability_adjustment(suggestion, stats)
        elif action == "add_constraint":
            return self._validate_constraint_addition(suggestion, stats)
        else:
            warning(f"Unknown LLM action: {action}")
            return False
    
    def _validate_split_suggestion(self, suggestion: Dict, stats: RuleStatistics) -> bool:
        """Validate rule split suggestion"""
        if 'new_rules' not in suggestion or len(suggestion['new_rules']) < 2:
            return False
        
        # Check if split is justified by signal distribution
        normal_ratio = stats.signal_distribution.get('NORMAL', 0.0)
        unstable_ratio = sum(v for k, v in stats.signal_distribution.items() 
                           if k != 'NORMAL')
        
        # Only split if there's significant mixed behavior
        if normal_ratio < 0.3 or unstable_ratio < 0.3:
            debug(f"Rule {stats.rule_id} doesn't show mixed behavior for split")
            return False
        
        return True
    
    def _validate_probability_adjustment(self, suggestion: Dict, stats: RuleStatistics) -> bool:
        """Validate probability adjustment suggestion"""
        if 'new_probability' not in suggestion:
            return False
        
        new_prob = suggestion['new_probability']
        if not 0.01 <= new_prob <= 0.95:
            warning(f"Probability {new_prob} outside allowed range")
            return False
        
        # Check if adjustment direction matches instability
        current_instability = stats.instability_score
        if current_instability > 0.5 and new_prob < 0.1:
            # Highly unstable rule being made very rare - questionable
            warning(f"Reducing probability of unstable rule {stats.rule_id}")
            return self.diversity_preserver.is_stable(stats.rule_id)
        
        return True
    
    def _validate_constraint_addition(self, suggestion: Dict, stats: RuleStatistics) -> bool:
        """Validate constraint addition suggestion"""
        if 'constraint' not in suggestion:
            return False
        
        # Basic constraint validation
        constraint = suggestion['constraint']
        if not isinstance(constraint, str) or len(constraint) > 100:
            return False
        
        return True
    
    def evolve_grammar(self, llm_suggestions: List[Dict[str, Any]] = None) -> Dict[str, float]:
        """
        Perform one evolution step.
        Returns new rule probabilities.
        """
        # Start with current probabilities from config
        rule_probs = {}
        for rule_id, rule_info in self.config['rules'].items():
            rule_probs[rule_id] = rule_info.get('base_probability', 0.5)
        
        # Apply LLM suggestions if validated
        applied_suggestions = 0
        if llm_suggestions:
            for suggestion in llm_suggestions:
                if self.apply_llm_suggestion(suggestion):
                    rule_id = suggestion['rule_id']
                    action = suggestion['action']
                    
                    if action == "adjust_probability":
                        rule_probs[rule_id] = suggestion['new_probability']
                        applied_suggestions += 1
                    elif action == "split_rule":
                        # Handle split - add new rules with probabilities
                        for new_rule in suggestion.get('new_rules', []):
                            new_id = f"{rule_id}_{new_rule.get('suffix', 'split')}"
                            rule_probs[new_id] = new_rule.get('probability', 0.1)
                        # Reduce original rule probability
                        rule_probs[rule_id] *= 0.5
                        applied_suggestions += 1
        
        # Adjust for diversity preservation
        final_probs = self.diversity_preserver.adjust_for_diversity(
            rule_probs, self.rule_stats
        )
        
        info(f"Grammar evolution: applied {applied_suggestions} suggestions, "
             f"{len(final_probs)} rules total")
        
        return final_probs
""",

"core/executor.py": r"""
import subprocess
import time
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional
from core.utils import debug, info, timeit
from core.signals import SignalClassifier
from core.jit_parser import JITTelemetryParser
from core.artifact import RuntimeResult, JITTelemetry

class V8Executor:
    """Execute JavaScript programs with V8 and collect telemetry"""
    
    def __init__(self, d8_path: str = "d8", flags: Optional[List[str]] = None,
                 timeout: float = 2.0, use_asan: bool = False):
        self.d8_path = Path(d8_path)
        self.timeout = timeout
        self.use_asan = use_asan
        
        # Load flags from config
        config_path = ROOT / "config" / "v8_flags.json"
        with open(config_path) as f:
            flag_config = json.load(f)
        
        self.base_flags = flag_config['common']
        if use_asan:
            self.base_flags.extend(flag_config['asan'])
        else:
            self.base_flags.extend(flag_config['debug'])
        
        # Add custom flags if provided
        if flags:
            self.base_flags.extend(flags)
        
        self.signal_classifier = SignalClassifier()
        self.jit_parser = JITTelemetryParser()
        
        # Validate d8 exists
        if not self.d8_path.exists():
            warning(f"d8 not found at {self.d8_path}")
    
    @timeit
    def execute(self, source: str, log_dir: Optional[Path] = None) -> RuntimeResult:
        """
        Execute JavaScript source and return detailed runtime result.
        
        Args:
            source: JavaScript source code
            log_dir: Directory to store execution logs
        
        Returns:
            RuntimeResult with telemetry
        """
        debug(f"Executing program ({len(source)} chars)")
        
        # Create temporary file for execution
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write(source)
            temp_js = Path(f.name)
        
        # Prepare log file if requested
        log_file = None
        if log_dir:
            log_dir.mkdir(parents=True, exist_ok=True)
            log_file = log_dir / f"v8_{int(time.time())}.log"
            # Replace %LOG% placeholder in flags
            flags = [f.replace("%LOG%", str(log_file)) for f in self.base_flags]
        else:
            flags = [f for f in self.base_flags if "%LOG%" not in f]
        
        # Prepare command
        cmd = [str(self.d8_path)] + flags + [str(temp_js)]
        
        start_time = time.time()
        result = {}
        
        try:
            # Execute with timeout
            process = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout,
                encoding='utf-8',
                errors='ignore'
            )
            
            exec_time = (time.time() - start_time) * 1000  # ms
            
            # Classify runtime behavior
            classification = self.signal_classifier.classify(
                process.returncode,
                process.stdout,
                process.stderr
            )
            
            # Parse JIT telemetry
            jit_info = {}
            if log_file and log_file.exists():
                jit_info = self.jit_parser.parse_log_file(str(log_file))
            else:
                # Fallback: parse from stderr
                jit_info = self.jit_parser.parse(process.stderr)
            
            result = {
                "label": classification["label"],
                "exit_code": process.returncode,
                "exec_time_ms": int(exec_time),
                "stdout": process.stdout,
                "stderr": process.stderr,
                "jit_telemetry": JITTelemetry(**jit_info),
                "signal_strength": classification.get("signal_strength", 0.0)
            }
            
            info(f"Execution: {classification['label']} "
                 f"(deopts: {jit_info.get('deopt_count', 0)}, "
                 f"time: {exec_time:.1f}ms)")
            
        except subprocess.TimeoutExpired:
            exec_time = self.timeout * 1000
            result = {
                "label": "HANG",
                "exit_code": -1,
                "exec_time_ms": int(exec_time),
                "stdout": "",
                "stderr": f"Timeout after {self.timeout}s",
                "jit_telemetry": JITTelemetry(),
                "signal_strength": 0.8
            }
            warning(f"Execution timed out after {self.timeout}s")
        
        except Exception as e:
            error(f"Execution failed: {e}")
            result = {
                "label": "CRASH",
                "exit_code": -1,
                "exec_time_ms": int((time.time() - start_time) * 1000),
                "stdout": "",
                "stderr": str(e),
                "jit_telemetry": JITTelemetry(),
                "signal_strength": 0.9
            }
        
        finally:
            # Clean up temp file
            try:
                temp_js.unlink()
            except:
                pass
        
        return RuntimeResult(**result)
    
    def execute_batch(self, sources: List[str], max_workers: int = 4) -> List[RuntimeResult]:
        """Execute multiple programs in parallel"""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        results = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_source = {
                executor.submit(self.execute, src): src 
                for src in sources[:100]  # Limit batch size
            }
            
            for future in as_completed(future_to_source):
                try:
                    result = future.result(timeout=self.timeout * 2)
                    results.append(result)
                except Exception as e:
                    error(f"Batch execution failed: {e}")
                    results.append(RuntimeResult(
                        label="CRASH",
                        exit_code=-1,
                        exec_time_ms=0,
                        stdout="",
                        stderr=str(e),
                        jit_telemetry=JITTelemetry(),
                        signal_strength=0.9
                    ))
        
        info(f"Batch execution: {len(results)} programs completed")
        return results
    
    def validate_environment(self) -> bool:
        """Validate that V8 environment is properly set up"""
        test_source = "print('Hello from V8');"
        
        try:
            result = self.execute(test_source)
            if result.label == "NORMAL" and "Hello from V8" in result.stdout:
                info("V8 environment validation passed")
                return True
            else:
                warning(f"V8 validation failed: {result.label}")
                return False
        except Exception as e:
            error(f"V8 validation error: {e}")
            return False
""",

"scripts/parse_ast.js": r"""
const esprima = require('esprima');

function parseAST(source) {
    try {
        const ast = esprima.parseScript(source, {
            range: true,
            loc: true,
            tokens: true,
            comment: true
        });
        
        // Add unique IDs to nodes
        let nextId = 0;
        function addIds(node, parentId = null) {
            node.id = nextId++;
            node.parentId = parentId;
            
            for (const key in node) {
                if (node[key] && typeof node[key] === 'object') {
                    if (Array.isArray(node[key])) {
                        node[key].forEach(child => {
                            if (child && typeof child === 'object' && child.type) {
                                addIds(child, node.id);
                            }
                        });
                    } else if (node[key].type) {
                        addIds(node[key], node.id);
                    }
                }
            }
        }
        
        addIds(ast);
        return ast;
    } catch (error) {
        return {
            type: 'ParseError',
            error: error.message,
            source: source.substring(0, 100) + '...'
        };
    }
}

// Read source from file
const fs = require('fs');
const source = fs.readFileSync(process.argv[2], 'utf8');

try {
    const ast = parseAST(source);
    console.log(JSON.stringify(ast, null, 2));
} catch (error) {
    console.error(JSON.stringify({
        error: error.message,
        sourcePreview: source.substring(0, 200)
    }));
}
""",

"scripts/run_once.py": r"""
#!/usr/bin/env python3
"""
Single program execution pipeline.
Demonstrates the core attribution-preserving flow.
"""
import random
import tempfile
import json
from pathlib import Path
from datetime import datetime

# Add project root to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.generator import DharmaGenerator
from core.executor import V8Executor
from core.artifact import ProgramArtifact, RuntimeResult
from core.graph import ProgramGraphBuilder
from core.utils import info, debug

def main():
    """Execute one generation-execution cycle with full attribution"""
    # Initialize components
    grammar_path = Path("config/grammar.dharma")
    config_path = Path("config/grammar_schema.json")
    
    generator = DharmaGenerator(grammar_path, grammar_config_path=config_path)
    executor = V8Executor(timeout=1.0)
    graph_builder = ProgramGraphBuilder(anonymize_rule_ids=True)
    
    # Generate program
    seed = random.randint(0, 2**32 - 1)
    info(f"Starting generation with seed {seed}")
    
    try:
        source, rule_trace = generator.generate(seed)
        
        # Validate trace coverage
        if not generator.validate_trace_coverage(source, rule_trace):
            warning("Trace coverage validation failed")
        
        # Execute
        runtime_result = executor.execute(source)
        
        # Create artifact
        artifact = ProgramArtifact(
            program_id=f"prog_{seed}_{int(datetime.now().timestamp())}",
            seed=seed,
            source=source,
            source_hash="",  # Will be auto-computed
            rule_trace=rule_trace,
            runtime=runtime_result,
            metadata={
                "generator": "dharma",
                "grammar_version": "1.0",
                "flags": executor.base_flags[:3]
            }
        )
        
        # Build graph
        graph = graph_builder.build(artifact)
        
        # Validate graph
        is_valid, issues = graph_builder.validate_graph(graph)
        if not is_valid:
            warning(f"Graph validation issues: {issues}")
        
        # Save results
        output_dir = Path("runs") / datetime.now().strftime("%Y%m%d")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Save artifact
        artifact_path = output_dir / f"{artifact.program_id}.json"
        artifact_path.write_text(artifact.to_json())
        
        # Save graph (simplified)
        graph_data = {
            "program_id": artifact.program_id,
            "num_nodes": graph.number_of_nodes(),
            "num_edges": graph.number_of_edges(),
            "node_types": dict(Counter(d['node_type'] 
                                     for _, d in graph.nodes(data=True) 
                                     if 'node_type' in d)),
            "edge_types": dict(Counter(d['edge_type'] 
                                     for _, _, d in graph.edges(data=True) 
                                     if 'edge_type' in d))
        }
        
        graph_path = output_dir / f"{artifact.program_id}_graph.json"
        graph_path.write_text(json.dumps(graph_data, indent=2))
        
        # Report
        info(f"Execution completed: {runtime_result.label}")
        info(f"  Deopts: {runtime_result.jit_telemetry.deopt_count}")
        info(f"  Signal strength: {runtime_result.signal_strength:.2f}")
        info(f"  Graph: {graph.number_of_nodes()} nodes, "
             f"{graph.number_of_edges()} edges")
        info(f"  Artifact saved: {artifact_path}")
        
        # If unstable, analyze rule impact
        if runtime_result.is_unstable:
            rule_freq = artifact.get_rule_frequency()
            info(f"  Rule frequencies in unstable program:")
            for rule_id, count in sorted(rule_freq.items(), 
                                       key=lambda x: x[1], reverse=True)[:5]:
                info(f"    {rule_id}: {count}")
        
        return artifact
        
    except Exception as e:
        error(f"Pipeline failed: {e}")
        raise

if __name__ == "__main__":
    main()
""",

"scripts/train_gnn.py": r"""
#!/usr/bin/env python3
"""
GNN training for structural deviation detection.
Trains on NORMAL programs, detects deviation in others.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.data import Data, DataLoader
from torch_geometric.nn import GATConv, global_mean_pool
import numpy as np
from typing import List, Dict, Any
import json

from core.utils import info, debug, warning
from core.artifact import ProgramArtifact
from core.graph import ProgramGraphBuilder

class StructuralDeviationGNN(nn.Module):
    """
    Graph Neural Network for learning structural patterns in NORMAL programs.
    Implemented as Variational Autoencoder for deviation detection.
    """
    
    def __init__(self, input_dim: int = 8, hidden_dim: int = 64, 
                 latent_dim: int = 32, num_heads: int = 4):
        super().__init__()
        
        # Encoder: Graph Attention Networks
        self.conv1 = GATConv(input_dim, hidden_dim, heads=num_heads)
        self.conv2 = GATConv(hidden_dim * num_heads, hidden_dim, heads=1)
        
        # Latent space (VAE)
        self.mu_layer = nn.Linear(hidden_dim, latent_dim)
        self.logvar_layer = nn.Linear(hidden_dim, latent_dim)
        
        # Decoder
        self.decoder_lin1 = nn.Linear(latent_dim, hidden_dim)
        self.decoder_conv1 = GATConv(hidden_dim, hidden_dim, heads=num_heads)
        self.decoder_conv2 = GATConv(hidden_dim * num_heads, input_dim, heads=1)
        
        # Norms
        self.bn1 = nn.BatchNorm1d(hidden_dim * num_heads)
        self.bn2 = nn.BatchNorm1d(hidden_dim)
        
        self.latent_dim = latent_dim
        self.hidden_dim = hidden_dim
        
    def encode(self, x, edge_index, batch) -> tuple:
        """Encode graph to latent distribution parameters"""
        # Graph convolution layers
        x = F.relu(self.bn1(self.conv1(x, edge_index)))
        x = F.relu(self.bn2(self.conv2(x, edge_index)))
        
        # Global pooling
        x = global_mean_pool(x, batch)
        
        # Latent parameters
        mu = self.mu_layer(x)
        logvar = self.logvar_layer(x)
        
        return mu, logvar
    
    def reparameterize(self, mu, logvar):
        """Reparameterization trick for VAE"""
        std = torch.exp(0.5 * logvar)
        eps = torch.randn_like(std)
        return mu + eps * std
    
    def decode(self, z, edge_index, batch_size, num_nodes):
        """Decode latent vector back to graph features"""
        # Expand latent vector to match node count
        z_expanded = z.repeat(num_nodes // batch_size + 1, 1)[:num_nodes]
        
        # Decoder layers
        x = F.relu(self.decoder_lin1(z_expanded))
        x = F.relu(self.decoder_conv1(x, edge_index))
        x = self.decoder_conv2(x, edge_index)
        
        return x
    
    def forward(self, x, edge_index, batch):
        """Full forward pass"""
        mu, logvar = self.encode(x, edge_index, batch)
        z = self.reparameterize(mu, logvar)
        recon = self.decode(z, edge_index, batch.max().item() + 1, x.size(0))
        
        return recon, mu, logvar
    
    def compute_deviation(self, x, edge_index, batch, 
                         normal_latents: torch.Tensor) -> float:
        """
        Compute deviation score: distance to nearest normal program in latent space.
        Lower score = more normal.
        """
        with torch.no_grad():
            mu, _ = self.encode(x, edge_index, batch)
            
            # For each graph in batch, find nearest normal latent
            batch_indices = batch.unique()
            deviation_scores = []
            
            for idx in batch_indices:
                graph_mu = mu[idx].unsqueeze(0)
                
                # Compute distances to all normal latents
                distances = torch.cdist(graph_mu, normal_latents)
                min_distance = distances.min().item()
                
                # Normalize by latent dimension
                deviation_scores.append(min_distance / np.sqrt(self.latent_dim))
            
            return np.mean(deviation_scores)

class GNNTrainer:
    """Manages GNN training and deviation detection"""
    
    def __init__(self, model: StructuralDeviationGNN, 
                 device: str = "cuda" if torch.cuda.is_available() else "cpu"):
        self.model = model.to(device)
        self.device = device
        self.optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
        
        # Store latent vectors of normal programs
        self.normal_latents: List[torch.Tensor] = []
        self.latent_dim = model.latent_dim
        
    def vae_loss(self, recon_x, x, mu, logvar, beta: float = 0.1):
        """VAE loss: reconstruction + KL divergence"""
        # Reconstruction loss (MSE)
        recon_loss = F.mse_loss(recon_x, x, reduction='mean')
        
        # KL divergence
        kl_loss = -0.5 * torch.sum(1 + logvar - mu.pow(2) - logvar.exp())
        kl_loss = kl_loss / x.size(0)  # Normalize by batch size
        
        return recon_loss + beta * kl_loss
    
    def train_epoch(self, loader: DataLoader) -> float:
        """Train for one epoch"""
        self.model.train()
        total_loss = 0
        
        for batch in loader:
            batch = batch.to(self.device)
            self.optimizer.zero_grad()
            
            recon, mu, logvar = self.model(batch.x, batch.edge_index, batch.batch)
            loss = self.vae_loss(recon, batch.x, mu, logvar)
            
            loss.backward()
            self.optimizer.step()
            
            total_loss += loss.item()
            
            # Store latents for normal programs (assuming all are NORMAL)
            with torch.no_grad():
                self.normal_latents.append(mu.detach().cpu())
        
        return total_loss / len(loader)
    
    def extract_normal_latents(self, loader: DataLoader):
        """Extract and store latent vectors of normal programs"""
        self.model.eval()
        self.normal_latents.clear()
        
        with torch.no_grad():
            for batch in loader:
                batch = batch.to(self.device)
                mu, _ = self.model.encode(batch.x, batch.edge_index, batch.batch)
                self.normal_latents.append(mu.cpu())
        
        # Concatenate all latents
        if self.normal_latents:
            self.normal_latents = torch.cat(self.normal_latents, dim=0)
            info(f"Stored {len(self.normal_latents)} normal latent vectors")
    
    def compute_batch_deviation(self, loader: DataLoader) -> List[float]:
        """Compute deviation scores for a batch of programs"""
        self.model.eval()
        deviations = []
        
        with torch.no_grad():
            for batch in loader:
                batch = batch.to(self.device)
                deviation = self.model.compute_deviation(
                    batch.x, batch.edge_index, batch.batch, self.normal_latents
                )
                deviations.append(deviation)
        
        return deviations
    
    def save_checkpoint(self, path: Path):
        """Save model and normal latents"""
        checkpoint = {
            'model_state_dict': self.model.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'normal_latents': self.normal_latents,
            'latent_dim': self.latent_dim
        }
        torch.save(checkpoint, path)
        info(f"Saved checkpoint to {path}")
    
    def load_checkpoint(self, path: Path):
        """Load model and normal latents"""
        checkpoint = torch.load(path, map_location=self.device)
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
        self.normal_latents = checkpoint['normal_latents']
        info(f"Loaded checkpoint from {path}")

def prepare_training_data(artifact_paths: List[Path], 
                         graph_builder: ProgramGraphBuilder) -> List[Data]:
    """Load artifacts and convert to PyTorch Geometric Data objects"""
    data_list = []
    
    for path in artifact_paths:
        try:
            # Load artifact
            artifact = ProgramArtifact.from_json(path.read_text())
            
            # Only use NORMAL programs for training
            if artifact.runtime.label != "NORMAL":
                continue
            
            # Build graph
            graph = graph_builder.build(artifact)
            
            # Convert to PyG Data
            data = graph_builder.to_pyg_data(graph)
            if isinstance(data, Data):
                data_list.append(data)
                
        except Exception as e:
            warning(f"Failed to process {path}: {e}")
    
    info(f"Prepared {len(data_list)} graphs for training")
    return data_list

def main():
    """Main training pipeline"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Train GNN for structural deviation')
    parser.add_argument('--data-dir', type=Path, default=Path('runs'),
                       help='Directory containing artifact JSON files')
    parser.add_argument('--epochs', type=int, default=50,
                       help='Number of training epochs')
    parser.add_argument('--batch-size', type=int, default=16,
                       help='Training batch size')
    parser.add_argument('--output', type=Path, default=Path('models/gnn'),
                       help='Output directory for models')
    
    args = parser.parse_args()
    
    # Setup
    args.output.mkdir(parents=True, exist_ok=True)
    graph_builder = ProgramGraphBuilder(anonymize_rule_ids=True)
    
    # Find artifact files
    artifact_files = list(args.data_dir.rglob("*.json"))
    info(f"Found {len(artifact_files)} artifact files")
    
    # Prepare training data
    train_data = prepare_training_data(artifact_files, graph_builder)
    
    if len(train_data) < 10:
        warning(f"Insufficient training data: {len(train_data)} graphs")
        warning("Need at least 10 NORMAL programs for meaningful training")
        return
    
    # Create data loader
    loader = DataLoader(train_data, batch_size=args.batch_size, shuffle=True)
    
    # Initialize model
    model = StructuralDeviationGNN(input_dim=8, hidden_dim=64, latent_dim=32)
    trainer = GNNTrainer(model)
    
    # Training loop
    info(f"Starting training for {args.epochs} epochs")
    for epoch in range(args.epochs):
        loss = trainer.train_epoch(loader)
        
        if (epoch + 1) % 10 == 0:
            info(f"Epoch {epoch+1}/{args.epochs}, Loss: {loss:.4f}")
    
    # Extract normal latents
    trainer.extract_normal_latents(loader)
    
    # Save model
    checkpoint_path = args.output / "gnn_checkpoint.pt"
    trainer.save_checkpoint(checkpoint_path)
    
    # Test deviation detection
    info("Testing deviation detection...")
    test_deviations = trainer.compute_batch_deviation(loader)
    
    if test_deviations:
        avg_deviation = np.mean(test_deviations)
        std_deviation = np.std(test_deviations)
        info(f"Normal program deviations: avg={avg_deviation:.3f}, std={std_deviation:.3f}")
        
        # Save deviation baseline
        baseline = {
            "avg_deviation": float(avg_deviation),
            "std_deviation": float(std_deviation),
            "num_normal_programs": len(train_data),
            "threshold_95pct": float(avg_deviation + 2 * std_deviation)
        }
        
        baseline_path = args.output / "deviation_baseline.json"
        baseline_path.write_text(json.dumps(baseline, indent=2))
        info(f"Saved deviation baseline to {baseline_path}")

if __name__ == "__main__":
    main()
""",

"requirements.txt": r"""
networkx>=3.0
torch>=2.0.0
torch-geometric>=2.3.0
numpy>=1.24.0
pydantic>=2.0.0
esprima>=4.0.0
jsonschema>=4.0.0
tqdm>=4.0.0
colorlog>=6.0.0
scikit-learn>=1.3.0
dataclasses-json>=0.6.0
"""
}

def main():
    if ROOT.exists():
        response = input("jitfuzz directory exists. Overwrite? [y/N]: ")
        if response.lower() != 'y':
            print("Aborted.")
            return
    
    # Create all files
    for path, content in FILES.items():
        full_path = ROOT / path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content.strip() + "\n")
        print(f"✓ Created {full_path}")
    
    # Create directory structure
    dirs = [
        "logs",
        "runs",
        "models/gnn",
        "data/artifacts",
        "data/graphs",
        "data/telemetry"
    ]
    
    for dir_path in dirs:
        (ROOT / dir_path).mkdir(parents=True, exist_ok=True)
        print(f"✓ Created directory {dir_path}")
    
    # Create README
    readme = ROOT / "README.md"
    readme.write_text("""# JITFuzz: Self-Improving JavaScript Fuzzer for V8

## Core Principles
1. **Traceability**: Every AST node linked to its generating grammar rule
2. **Empirical Grounding**: All evolution decisions based on runtime evidence
3. **Diversity Preservation**: Grammar entropy maintained to prevent collapse
4. **Explainability**: Every decision can be traced and audited

## Key Components
- `core/generator.py`: Dharma-based generation with rule attribution
- `core/graph.py`: Attributed AST+Rule graph construction
- `core/evolution.py`: Conservative grammar evolution with LLM gating
- `core/gnn.py`: Structural deviation detection (VAE-based)
- `scripts/train_gnn.py`: GNN training pipeline

## Getting Started
1. Install dependencies: `pip install -r requirements.txt`
2. Install Dharma and build V8 with debug symbols
3. Test single run: `python scripts/run_once.py`
4. Train GNN: `python scripts/train_gnn.py --epochs 50`

## Evolution Workflow
1. Generate programs with traced rule applications
2. Execute and classify runtime behavior
3. Build attributed graphs
4. Train GNN on NORMAL programs
5. Compute deviation scores for unstable programs
6. Aggregate rule statistics
7. Use LLM (constrained) to propose grammar refinements
8. Validate and integrate conservative changes

## Safety Features
- Rule anonymization to prevent GNN from learning rule IDs
- Entropy constraints to maintain grammar diversity
- Empirical validation gates for all LLM suggestions
- Full reproducibility through artifact serialization
""")
    
    print(f"\n✅ Project structure created at {ROOT}")
    print("\nNext steps:")
    print("1. Install Dharma: https://github.com/mlsecproject/dharma")
    print("2. Build V8 with: `is_debug=true dcheck_always_on=true`")
    print("3. Run: `python scripts/run_once.py` to test the pipeline")
    print("4. Review core/evolution.py for the LLM constraint interface")

if __name__ == "__main__":
    main()
