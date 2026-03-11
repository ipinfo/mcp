from typing import NotRequired, TypedDict


class LiteResponse(TypedDict):
    ip: str
    hostname: NotRequired[str]
    asn: str
    as_name: str
    as_domain: str
    country_code: str
    country: str
    continent_code: str
    continent: str


# --- Lookup API response (Core / Plus) ---


class GeoObject(TypedDict):
    city: str
    region: str
    region_code: str
    country: str
    country_code: str
    continent: str
    continent_code: str
    latitude: float
    longitude: float
    timezone: str
    postal_code: str
    # Plus-only fields
    dma_code: NotRequired[str]
    geoname_id: NotRequired[int]
    radius: NotRequired[int]
    last_changed: NotRequired[str]


class ASObject(TypedDict):
    asn: str
    name: str
    domain: str
    type: str
    # Plus-only
    last_changed: NotRequired[str]


class AnonymousObject(TypedDict):
    is_proxy: bool
    is_relay: bool
    is_tor: bool
    is_vpn: bool
    # Plus-only
    name: NotRequired[str]


class MobileObject(TypedDict):
    name: str
    mcc: str
    mnc: str


# We define LookupResponse like this because of the
# "as" field, since it's a keyword we can't use it as
# a class field so we fallback to this definition
LookupResponse = TypedDict(
    "LookupResponse",
    {
        "ip": str,
        "hostname": NotRequired[str],
        "geo": GeoObject,
        "as": NotRequired[ASObject],
        "anonymous": NotRequired[AnonymousObject],
        "mobile": NotRequired[MobileObject],
        # Network flags (Core+)
        "is_anonymous": NotRequired[bool],
        "is_anycast": NotRequired[bool],
        "is_hosting": NotRequired[bool],
        "is_mobile": NotRequired[bool],
        "is_satellite": NotRequired[bool],
    },
)


# --- Residential Proxy API response ---


class ResproxyResponse(TypedDict):
    ip: str
    service: str
    last_seen: str
    percent_days_seen: int


# --- /me API response ---


class RequestsInfo(TypedDict):
    day: int
    month: int
    limit: int
    remaining: int


class FeatureQuota(TypedDict):
    daily: int
    monthly: int
    # Feature-specific optional fields
    result_limit: NotRequired[int]
    firmographics: NotRequired[bool]
    org_additional: NotRequired[bool]
    vpn_provider: NotRequired[bool]


class MeResponse(TypedDict):
    token: str
    requests: RequestsInfo
    features: NotRequired[dict[str, FeatureQuota]]


# --- Batch API response ---
# The batch endpoint returns a dict keyed by the input keys.
# e.g. {"lite/8.8.8.8": LiteResponse, "lookup/1.1.1.1": LookupResponse, ...}
# Since keys can mix types, the batch response is typed as:

BatchResponse = dict[str, LiteResponse | LookupResponse | ResproxyResponse | dict[str, object]]
