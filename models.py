import json
from sqlite3 import Row
from typing import List, Optional, Tuple

from lnbits.db import FilterModel, FromRowModel
from pydantic import BaseModel

from .helpers import format_amount, is_ws_url, normalize_identifier, validate_pub_key


class CustomCost(BaseModel):
    bracket: int
    amount: float

    def validate_data(self):
        assert self.amount >= 0, "Custom cost must be positive."


class Promotion(BaseModel):
    code: str = ""
    buyer_discount_percent: int
    referer_bonus_percent: int
    selected_referer: Optional[str] = None

    def validate_data(self):
        assert (
            0 <= self.buyer_discount_percent <= 100
        ), f"Discount percent for '{self.code}' must be between 0 and 100."
        assert (
            0 <= self.referer_bonus_percent <= 100
        ), f"Referer percent for '{self.code}' must be between 0 and 100."
        assert self.buyer_discount_percent + self.referer_bonus_percent <= 100, (
            f"Discount and Referer for '{self.code}'" " must be less than 100%."
        )


class RotateAddressData(BaseModel):
    secret: str
    pubkey: str


class UpdateAddressData(BaseModel):
    pubkey: Optional[str] = None
    relays: Optional[List[str]] = None

    def validate_data(self):
        self.validate_relays_urls()
        self.validate_pubkey()

    def validate_relays_urls(self):
        if not self.relays:
            return
        for r in self.relays:
            if not is_ws_url(r):
                raise ValueError(f"Relay '{r}' is not valid!")

    def validate_pubkey(self):
        if self.pubkey and self.pubkey != "":
            self.pubkey = validate_pub_key(self.pubkey)


class CreateAddressData(BaseModel):
    domain_id: str
    local_part: str
    pubkey: str = ""
    years: int = 1
    relays: Optional[List[str]] = None
    create_invoice: bool = False


class DomainCostConfig(BaseModel):
    max_years: int = 1
    char_count_cost: List[CustomCost] = []
    rank_cost: List[CustomCost] = []
    promotions: List[Promotion] = []

    def validate_data(self):
        for cost in self.char_count_cost:
            cost.validate_data()

        for cost in self.rank_cost:
            cost.validate_data()

        assert (
            1 < self.max_years < 100
        ), "Maximum allowed years must be between 1 and 100."
        promo_codes = []
        for promo in self.promotions:
            promo.validate_data()
            assert (
                promo.code not in promo_codes
            ), f"Duplicate promo code: '{promo.code}'."
            promo_codes.append(promo.code)


class CreateDomainData(BaseModel):
    wallet: str
    currency: str
    cost: float
    domain: str
    cost_config: Optional[DomainCostConfig] = None

    def validate_data(self):
        assert self.cost >= 0, "Domain cost must be positive."
        if self.cost_config:
            self.cost_config.validate_data()


class EditDomainData(BaseModel):
    id: str
    currency: str
    cost: float
    cost_config: Optional[DomainCostConfig] = None

    def validate_data(self):
        assert self.cost >= 0, "Domain cost must be positive."
        if self.cost_config:
            self.cost_config.validate_data()

    @classmethod
    def from_row(cls, row: Row) -> "EditDomainData":
        return cls(**dict(row))


class IdentifierRanking(BaseModel):
    name: str
    rank: int

    @classmethod
    def from_row(cls, row: Row) -> "IdentifierRanking":
        return cls(**dict(row))


class PublicDomain(BaseModel):
    id: str
    currency: str
    cost: float
    domain: str

    @classmethod
    def from_row(cls, row: Row) -> "PublicDomain":
        return cls(**dict(row))


class Domain(PublicDomain):
    wallet: str
    cost_config: DomainCostConfig = DomainCostConfig()
    time: int

    def price_for_identifier(
        self, identifier: str, years: int, rank: Optional[int] = None
    ) -> Tuple[float, str]:
        assert (
            1 <= years <= self.cost_config.max_years
        ), f"Number of years must be between '1' and '{self.cost_config.max_years}'."

        identifier = normalize_identifier(identifier)
        max_amount = self.cost
        reason = ""

        for char_cost in self.cost_config.char_count_cost:
            if len(identifier) <= char_cost.bracket and max_amount < char_cost.amount:
                max_amount = char_cost.amount
                reason = f"{len(identifier)} characters"

        if not rank:
            return max_amount * years, reason

        for rank_cost in self.cost_config.rank_cost:
            if rank <= rank_cost.bracket and max_amount < rank_cost.amount:
                max_amount = rank_cost.amount
                reason = f"Top {rank_cost.bracket} identifier"

        return max_amount * years, reason

    def public_data(self):
        data = dict(PublicDomain(**dict(self)))
        data["max_years"] = self.cost_config.max_years
        return data

    @classmethod
    def from_row(cls, row: Row) -> "Domain":
        domain = cls(**dict(row))
        if row["cost_extra"]:
            domain.cost_config = DomainCostConfig(**json.loads(row["cost_extra"]))

        return domain


class LnAddressConfig(BaseModel):
    wallet: str
    min: int = 1
    max: int = 10_000_000
    pay_link_id: Optional[str] = ""


class AddressConfig(BaseModel):
    currency: Optional[str] = None
    price: Optional[float] = None
    price_in_sats: Optional[float] = None
    payment_hash: Optional[str] = None
    reimburse_payment_hash: Optional[str] = None
    activated_by_owner: bool = False
    years: int = 1
    max_years: int = 1
    relays: List[str] = []

    ln_address: LnAddressConfig = LnAddressConfig(wallet="")


class Address(FromRowModel):
    id: str
    owner_id: Optional[str] = None
    domain_id: str
    local_part: str
    pubkey: str
    active: bool
    time: int
    reimburse_amount: int = 0
    expires_at: Optional[float]

    config: AddressConfig = AddressConfig()

    @property
    def has_pubkey(self):
        return self.pubkey != ""

    @classmethod
    def from_row(cls, row: Row) -> "Address":
        address = cls(**dict(row))
        if row["extra"]:
            address.config = AddressConfig(**json.loads(row["extra"]))
        return address


class AddressStatus(BaseModel):
    identifier: str
    available: bool = False
    price: Optional[float] = None
    price_in_sats: Optional[float] = None
    price_reason: Optional[str] = None
    currency: Optional[str] = None

    @property
    def price_formatted(self) -> str:
        if self.available and self.price and self.currency:
            return format_amount(self.price, self.currency)

        return ""


class AddressFilters(FilterModel):
    domain_id: str
    local_part: str
    reimburse_amount: str
    pubkey: str
    active: bool
    time: int


class Nip5Settings(BaseModel):
    cloudflare_access_token: Optional[str] = None
    lnaddress_api_endpoint: Optional[str] = "https://nostr.com"
    lnaddress_api_admin_key: Optional[str] = ""

    @classmethod
    def from_row(cls, row: Row) -> "Nip5Settings":
        return cls(**dict(json.loads(row["settings"])))
