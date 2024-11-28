import json
from sqlite3 import Row
from typing import List, Optional, Tuple

from lnbits.db import FilterModel, FromRowModel
from lnbits.utils.exchange_rates import fiat_amount_as_satoshis
from pydantic import BaseModel

from .helpers import format_amount, is_ws_url, normalize_identifier, validate_pub_key


class CustomCost(BaseModel):
    bracket: int
    amount: float

    def validate_data(self):
        assert self.bracket >= 0, "Bracket must be positive."
        assert self.amount >= 0, "Custom cost must be positive."


class PriceData(BaseModel):
    currency: str
    price: float
    discount: float = 0
    referer_bonus: float = 0

    reason: str

    async def price_sats(self) -> float:
        if self.price == 0:
            return 0
        if self.currency == "sats":
            return self.price
        return await fiat_amount_as_satoshis(self.price, self.currency)

    async def discount_sats(self) -> float:
        if self.discount == 0:
            return 0
        if self.currency == "sats":
            return self.discount
        return await fiat_amount_as_satoshis(self.discount, self.currency)

    async def referer_bonus_sats(self) -> float:
        if self.referer_bonus == 0:
            return 0
        if self.currency == "sats":
            return self.referer_bonus
        return await fiat_amount_as_satoshis(self.referer_bonus, self.currency)


class Promotion(BaseModel):
    code: str = ""
    buyer_discount_percent: float
    referer_bonus_percent: float
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


class PromoCodeStatus(BaseModel):
    buyer_discount: Optional[float] = None
    allow_referer: bool = False
    referer: Optional[str] = None


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
    promo_code: Optional[str] = None
    referer: Optional[str] = None
    create_invoice: bool = False

    def normalize(self):
        self.local_part = self.local_part.strip()
        self.pubkey = self.pubkey.strip()
        if self.relays:
            self.relays = [r.strip() for r in self.relays]

        if self.promo_code:
            self.promo_code = self.promo_code.strip()
            if "@" in self.promo_code:
                elements = self.promo_code.rsplit("@")
                self.promo_code = elements[0]
                self.referer = elements[1]

        if self.referer:
            self.referer = self.referer.strip()


class DomainCostConfig(BaseModel):
    max_years: int = 1
    char_count_cost: List[CustomCost] = []
    rank_cost: List[CustomCost] = []
    promotions: List[Promotion] = []

    def apply_promo_code(
        self, amount: float, promo_code: Optional[str] = None
    ) -> Tuple[float, float]:
        if promo_code is None:
            return 0, 0
        promotion = next((p for p in self.promotions if p.code == promo_code), None)
        if not promotion:
            return 0, 0

        discount = amount * (promotion.buyer_discount_percent / 100)
        referer_bonus = amount * (promotion.referer_bonus_percent / 100)
        return round(discount, 2), round(referer_bonus, 2)

    def get_promotion(self, promo_code: Optional[str] = None) -> Optional[Promotion]:
        if promo_code is None:
            return None
        return next((p for p in self.promotions if p.code == promo_code), None)

    def promo_code_buyer_discount(self, promo_code: Optional[str] = None) -> float:
        promotion = self.get_promotion(promo_code)
        if not promotion:
            return 0
        return promotion.buyer_discount_percent

    def promo_code_referer(
        self, promo_code: Optional[str] = None, default_referer: Optional[str] = None
    ) -> Optional[str]:
        promotion = self.get_promotion(promo_code)
        if not promotion:
            return None
        if promotion.referer_bonus_percent == 0:
            return None
        if promotion.selected_referer:
            return promotion.selected_referer

        return default_referer

    def promo_code_allows_referer(self, promo_code: Optional[str] = None) -> bool:
        promotion = self.get_promotion(promo_code)
        if not promotion:
            return False

        return promotion.referer_bonus_percent > 0 and not promotion.selected_referer

    def promo_code_status(self, promo_code: Optional[str] = None) -> PromoCodeStatus:
        return PromoCodeStatus(
            buyer_discount=self.promo_code_buyer_discount(promo_code),
            allow_referer=self.promo_code_allows_referer(promo_code),
            referer=self.promo_code_referer(promo_code),
        )

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

    async def price_for_identifier(
        self,
        identifier: str,
        years: int,
        rank: Optional[int] = None,
        promo_code: Optional[str] = None,
    ) -> PriceData:
        assert (
            1 <= years <= self.cost_config.max_years
        ), f"Number of years must be between '1' and '{self.cost_config.max_years}'."

        identifier = normalize_identifier(identifier)
        max_amount, reason = self.cost, ""

        for char_cost in self.cost_config.char_count_cost:
            if len(identifier) <= char_cost.bracket and max_amount < char_cost.amount:
                max_amount = char_cost.amount
                reason = f"{len(identifier)} characters"

        if rank:
            for rank_cost in self.cost_config.rank_cost:
                if rank <= rank_cost.bracket and max_amount < rank_cost.amount:
                    max_amount = rank_cost.amount
                    reason = f"Top {rank_cost.bracket} identifier"

        full_price = max_amount * years
        discount, referer_bonus = self.cost_config.apply_promo_code(
            full_price, promo_code
        )

        return PriceData(
            currency=self.currency,
            price=full_price - discount,
            discount=discount,
            referer_bonus=referer_bonus,
            reason=reason,
        )

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
    promo_code: Optional[str] = None
    referer: Optional[str] = None
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
    is_free: bool
    time: int
    reimburse_amount: int = 0
    expires_at: Optional[float]

    config: AddressConfig = AddressConfig()

    promo_code_status: PromoCodeStatus = PromoCodeStatus()

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
    free_identifier: Optional[str] = None
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
