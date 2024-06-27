import json
from sqlite3 import Row
from typing import List, Optional

from fastapi.param_functions import Query
from pydantic import BaseModel


class CostMultipier(BaseModel):
    bracket: int
    multiplier: float


class RotateAddressData(BaseModel):
    owner_id: Optional[str] = None
    pubkey: str


class CreateAddressData(BaseModel):
    domain_id: str
    local_part: str
    pubkey: str
    active: bool = False


class DomainCostConfig(BaseModel):
    enable_multipliers: bool = False
    length_multipliers: List[CostMultipier] = []
    rank_multipliers: List[CostMultipier] = []


class CreateDomainData(BaseModel):
    wallet: str
    currency: str
    amount: float = Query(..., ge=0.01)
    domain: str
    cost_config: Optional[DomainCostConfig] = None


class EditDomainData(BaseModel):
    id: str
    currency: str
    amount: float = Query(..., ge=0.01)
    cost_config: Optional[DomainCostConfig] = None

    @classmethod
    def from_row(cls, row: Row) -> "EditDomainData":
        return cls(**dict(row))


class PublicDomain(BaseModel):
    id: str
    currency: str
    amount: int  # todo: only final cost should be available
    domain: str

    @classmethod
    def from_row(cls, row: Row) -> "PublicDomain":
        return cls(**dict(row))


class Domain(PublicDomain):
    wallet: str
    cost_config: DomainCostConfig = DomainCostConfig()
    time: int

    @classmethod
    def from_row(cls, row: Row) -> "Domain":
        domain = cls(**dict(row))
        if row["cost_extra"]:
            domain.cost_config = DomainCostConfig(**json.loads(row["cost_extra"]))

        return domain


class Address(BaseModel):
    id: str
    owner_id: Optional[str] = None
    domain_id: str
    local_part: str
    pubkey: str
    active: bool
    time: int

    @classmethod
    def from_row(cls, row: Row) -> "Address":
        return cls(**dict(row))


class AddressStatus(BaseModel):
    available: bool = False
    reserved: bool = False
