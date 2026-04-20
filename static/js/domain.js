const RANK_BRACKETS = [
  200, 500, 1000, 2000, 5000, 10000, 20000, 50000, 100000, 200000, 500000,
  1000000
]

function normalizeIdentifier(value) {
  return (value || '').toLowerCase().trim()
}

function formatAmount(amount, currency) {
  if (amount === null || amount === undefined || isNaN(amount)) return ''
  if (currency === 'sats') {
    return `${Math.round(amount).toLocaleString()} sats`
  }
  return `${Number(amount).toFixed(2)} ${currency || ''}`.trim()
}

window.app = Vue.createApp({
  el: '#vue',
  mixins: [window.windowMixin],
  data() {
    return {
      currencyOptions: [],
      rankBracketOptions: RANK_BRACKETS.map(r => ({
        label: `Top ${r.toLocaleString()}`,
        value: r
      })),
      domainForm: {
        unlockTransferSecret: false,
        data: domain
      },
      previewName: 'yourname',
      previewRank: 0
    }
  },
  computed: {
    hasCharCountRules() {
      return (this.domainForm.data.cost_extra.char_count_cost || []).length > 0
    },
    hasRankRules() {
      return (this.domainForm.data.cost_extra.rank_cost || []).length > 0
    },
    hasPromotions() {
      return (this.domainForm.data.cost_extra.promotions || []).length > 0
    },
    preview() {
      const base = Number(this.domainForm.data.cost) || 0
      const identifier = normalizeIdentifier(this.previewName)
      const len = identifier.length

      let lengthBonus = 0
      let lengthReason = ''
      for (const item of this.domainForm.data.cost_extra.char_count_cost || []) {
        const bracket = Number(item.bracket) || 0
        const amount = Number(item.amount) || 0
        if (len > 0 && len <= bracket && amount > base) {
          const bonus = amount - base
          if (bonus > lengthBonus) {
            lengthBonus = bonus
            lengthReason = `Names up to ${bracket} characters`
          }
        }
      }

      let rankBonus = 0
      let rankReason = ''
      const rank = Number(this.previewRank) || 0
      if (rank > 0) {
        for (const item of this.domainForm.data.cost_extra.rank_cost || []) {
          const bracket = Number(item.bracket) || 0
          const amount = Number(item.amount) || 0
          if (rank <= bracket && amount > base + lengthBonus) {
            const bonus = amount - (base + lengthBonus)
            if (amount - base > rankBonus) {
              rankBonus = amount - base - lengthBonus
              rankReason = `Top ${bracket.toLocaleString()}`
            }
          }
        }
      }

      const pricePerYear = base + lengthBonus + rankBonus
      return {lengthBonus, lengthReason, rankBonus, rankReason, pricePerYear}
    }
  },
  methods: {
    formatPrice(amount) {
      return formatAmount(amount, this.domainForm.data.currency)
    },
    copySignupLink() {
      const url = `${window.location.origin}/nostrnip5/signup/${this.domainForm.data.id}`
      this.copyText(url, 'Signup link copied')
    },
    saveDomain: async function () {
      try {
        await LNbits.api.request(
          'PUT',
          '/nostrnip5/api/v1/domain',
          _.findWhere(this.g.user.wallets, {id: this.domainForm.data.wallet})
            .adminkey,
          this.domainForm.data
        )
        this.$q.notify({type: 'positive', message: 'Domain updated'})
      } catch (error) {
        LNbits.utils.notifyApiError(error)
      }
    },
    addCharCountCost() {
      this.domainForm.data.cost_extra.char_count_cost.push({
        bracket: 4,
        amount: Number(this.domainForm.data.cost) || 1
      })
    },
    removeCharCountCost(index) {
      this.domainForm.data.cost_extra.char_count_cost.splice(index, 1)
    },
    addRankCost() {
      this.domainForm.data.cost_extra.rank_cost.push({
        bracket: 1000,
        amount: Number(this.domainForm.data.cost) || 1
      })
    },
    removeRankCost(index) {
      this.domainForm.data.cost_extra.rank_cost.splice(index, 1)
    },
    addPromotion() {
      this.domainForm.data.cost_extra.promotions.push({
        code: '',
        buyer_discount_percent: 0,
        referer_bonus_percent: 0,
        selected_referer: ''
      })
    },
    removePromotion(index) {
      this.domainForm.data.cost_extra.promotions.splice(index, 1)
    }
  },
  created() {
    if (!this.domainForm.data.cost_extra.promotions) {
      this.domainForm.data.cost_extra.promotions = []
    }
    LNbits.api
      .request('GET', '/api/v1/currencies')
      .then(response => {
        this.currencyOptions = ['sats', ...response.data]
      })
      .catch(LNbits.utils.notifyApiError)
  }
})
