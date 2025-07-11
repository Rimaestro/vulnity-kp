from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from pydantic import BaseModel, Field, validator, HttpUrl


class VulnerabilityType(str, Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    DIRECTORY_TRAVERSAL = "directory_traversal"
    FILE_INCLUSION = "file_inclusion"
    OPEN_REDIRECT = "open_redirect"
    CSRF = "csrf"
    OTHER = "other"


class VulnerabilitySeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    PATCH = "PATCH"


class HttpParameter(BaseModel):
    name: str
    value: str
    param_type: str = Field(..., description="Type of parameter (query, body, cookie, header)")


class HttpRequest(BaseModel):
    url: str
    method: HttpMethod
    headers: Dict[str, str] = {}
    cookies: Dict[str, str] = {}
    params: List[HttpParameter] = []
    body: Optional[Union[str, Dict[str, Any]]] = None


class HttpResponse(BaseModel):
    status_code: int
    headers: Dict[str, str] = {}
    body: Optional[str] = None
    time_ms: float = 0.0


class Vulnerability(BaseModel):
    id: Optional[str] = None
    name: str
    description: str
    type: VulnerabilityType
    severity: VulnerabilitySeverity
    request: HttpRequest
    response: Optional[HttpResponse] = None
    evidence: str
    payload: Optional[str] = None
    cwe_id: Optional[int] = None
    remediation: Optional[str] = None
    discovered_at: datetime = Field(default_factory=datetime.now)
    additional_info: Dict[str, Any] = {}

    @validator("id", pre=True, always=True)
    def set_id(cls, v):
        import uuid
        return v or str(uuid.uuid4())


class ScanRequestOptions(BaseModel):
    max_depth: int = Field(default=3, ge=1)
    threads: int = Field(default=10, ge=1)
    timeout: int = Field(default=30, ge=1)
    follow_redirects: bool = True


class ScanRequest(BaseModel):
    url: str = Field(..., description="URL target untuk dipindai")
    scan_types: List[str] = Field(..., description="Daftar tipe pemindaian yang akan dijalankan")
    options: ScanRequestOptions = Field(default_factory=ScanRequestOptions)

    @validator("url")
    def validate_url(cls, v):
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL harus dimulai dengan http:// atau https://")
        return v


class ScanOptions(BaseModel):
    scan_types: List[str] = []
    max_depth: int = 3
    threads: int = 10
    timeout: int = 30
    cookies: Dict[str, str] = {}
    headers: Dict[str, str] = {}
    auth: Dict[str, str] = {}
    follow_redirects: bool = True
    scan_ajax: bool = True
    custom_parameters: Dict[str, Any] = {}


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanStatistics(BaseModel):
    urls_crawled: int = 0
    forms_tested: int = 0
    vulnerabilities_found: int = 0
    elapsed_time: float = 0.0
    requests_sent: int = 0
    scan_status: ScanStatus = ScanStatus.PENDING
    plugins_executed: Dict[str, int] = {}
    current_url: Optional[str] = None


class ScanResult(BaseModel):
    scan_id: str
    target_url: str
    start_time: datetime
    end_time: Optional[datetime] = None
    status: ScanStatus
    vulnerabilities: List[Vulnerability] = []
    statistics: ScanStatistics = Field(default_factory=ScanStatistics)
    options: ScanOptions 