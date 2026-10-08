from pydantic import BaseModel, ConfigDict


class HostCreate(BaseModel):
    hostname: str
    platform: str
    ip_address: str | None = None


class HostResponse(BaseModel):
    id: int
    hostname: str
    platform: str
    ip_address: str | None = None

    model_config = ConfigDict(from_attributes=True)