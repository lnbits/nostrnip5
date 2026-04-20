const NPUB_REGEX = /^npub1[023456789acdefghjklmnpqrstuvwxyz]{58,}$/
const HEX_REGEX = /^[0-9a-f]{64}$/i

function classifyPubkey(value) {
  if (!value) return 'empty'
  if (NPUB_REGEX.test(value)) return 'npub'
  if (HEX_REGEX.test(value)) return 'hex'
  return 'invalid'
}

function formatPrice(amount, currency) {
  if (amount === null || amount === undefined) return ''
  if (currency === 'sats') {
    return `${Math.round(amount).toLocaleString()} sats`
  }
  return `${Number(amount).toFixed(2)} ${currency}`
}

window.app = Vue.createApp({
  el: '#vue',
  mixins: [window.windowMixin],
  data() {
    return {
      base_url,
      domain,
      domain_id,
      currency,
      baseCost,
      maxYears,
      step: 1,
      form: {
        local_part: initialIdentifier || '',
        pubkey: '',
        years: 1,
        promo_code: '',
        referer: ''
      },
      availability: {
        state: 'idle',
        price: null,
        priceFormatted: '',
        priceReason: '',
        message: ''
      },
      searchTimer: null,
      invoice: null,
      paymentChecker: null,
      creatingInvoice: false,
      success: false,
      successData: {
        local_part: '',
        address_id: '',
        rotation_secret: ''
      }
    }
  },
  computed: {
    domainInitial() {
      return (this.domain || '?').charAt(0).toUpperCase()
    },
    previewHandle() {
      const name = this.form.local_part || 'yourname'
      return `${name}@${this.domain}`
    },
    pubkeyState() {
      return classifyPubkey(this.form.pubkey)
    },
    yearOptions() {
      const max = Math.max(1, parseInt(this.maxYears) || 1)
      const opts = []
      for (let i = 1; i <= max; i++) {
        opts.push({label: `${i} ${i === 1 ? 'year' : 'years'}`, value: i})
      }
      return opts
    },
    totalFormatted() {
      if (!this.availability.price) return ''
      const total = this.availability.price * this.form.years
      return formatPrice(total, this.availability.currency || this.currency)
    },
    successHandle() {
      return `${this.successData.local_part}@${this.domain}`
    },
    recoveryLink() {
      const origin = window.location.origin
      return (
        `${origin}/nostrnip5/rotate/${this.domain_id}/` +
        `${this.successData.address_id}?secret=${this.successData.rotation_secret}`
      )
    }
  },
  watch: {
    'form.local_part'() {
      this.scheduleAvailabilityCheck()
    },
    'form.years'() {
      // Re-check price since some domains price per-year differently
      if (this.form.local_part) this.scheduleAvailabilityCheck(0)
    }
  },
  methods: {
    scheduleAvailabilityCheck(delay = 400) {
      clearTimeout(this.searchTimer)
      const q = (this.form.local_part || '').trim()
      if (!q) {
        this.availability = {
          state: 'idle',
          price: null,
          priceFormatted: '',
          priceReason: '',
          message: ''
        }
        return
      }
      this.availability.state = 'checking'
      this.searchTimer = setTimeout(() => this.checkAvailability(q), delay)
    },
    checkAvailability(q) {
      const params = new URLSearchParams({q, years: this.form.years})
      axios
        .get(`/nostrnip5/api/v1/domain/${this.domain_id}/search?${params}`)
        .then(res => {
          const data = res.data || {}
          if ((data.identifier || '').trim() !== q.toLowerCase()) {
            // Stale response, ignore
            return
          }
          if (data.available && data.price) {
            this.availability = {
              state: 'available',
              price: data.price,
              currency: data.currency || this.currency,
              priceFormatted: formatPrice(
                data.price,
                data.currency || this.currency
              ),
              priceReason: data.price_reason || '',
              message: ''
            }
          } else if (data.available && !data.price) {
            this.availability = {
              state: 'invalid',
              price: null,
              priceFormatted: '',
              priceReason: '',
              message: 'This name cannot be priced. Try a different one.'
            }
          } else {
            this.availability = {
              state: 'taken',
              price: null,
              priceFormatted: '',
              priceReason: '',
              message: 'That name is already taken'
            }
          }
        })
        .catch(err => {
          this.availability = {
            state: 'invalid',
            price: null,
            priceFormatted: '',
            priceReason: '',
            message:
              (err.response && err.response.data && err.response.data.detail) ||
              'Could not check availability'
          }
        })
    },
    goToStep(n) {
      this.step = n
    },
    async pasteFromClipboard() {
      try {
        const text = await navigator.clipboard.readText()
        this.form.pubkey = (text || '').trim()
      } catch (e) {
        this.$q.notify({
          type: 'warning',
          message: 'Clipboard access denied'
        })
      }
    },
    truncate(value, head = 10, tail = 6) {
      if (!value) return ''
      if (value.length <= head + tail + 1) return value
      return `${value.slice(0, head)}…${value.slice(-tail)}`
    },
    createAddress() {
      this.creatingInvoice = true
      const payload = {
        domain_id: this.domain_id,
        local_part: this.form.local_part,
        pubkey: this.form.pubkey,
        years: this.form.years,
        create_invoice: true
      }
      if (this.form.promo_code) payload.promo_code = this.form.promo_code
      if (this.form.referer) payload.referer = this.form.referer

      axios
        .post(
          `/nostrnip5/api/v1/public/domain/${this.domain_id}/address`,
          payload
        )
        .then(res => {
          this.invoice = res.data
          this.startPaymentPolling()
        })
        .catch(err => {
          LNbits.utils.notifyApiError(err)
        })
        .finally(() => {
          this.creatingInvoice = false
        })
    },
    startPaymentPolling() {
      if (!this.invoice || !this.invoice.payment_hash) return
      this.paymentChecker = setInterval(() => {
        axios
          .get(
            `/nostrnip5/api/v1/domain/${this.domain_id}` +
              `/payments/${this.invoice.payment_hash}`
          )
          .then(res => {
            if (res.data && res.data.paid) {
              clearInterval(this.paymentChecker)
              this.paymentChecker = null
              this.successData = {
                local_part: this.form.local_part,
                address_id: this.invoice.id,
                rotation_secret: this.invoice.rotation_secret
              }
              this.success = true
            }
          })
          .catch(() => {})
      }, 3000)
    },
    downloadRecovery() {
      const body =
        `Nostr identity recovery link\n\n` +
        `Handle: ${this.successHandle}\n` +
        `Rotation URL: ${this.recoveryLink}\n\n` +
        `Keep this file safe. Without this link you cannot reassign this ` +
        `handle to a new Nostr key.\n`
      const blob = new Blob([body], {type: 'text/plain'})
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${this.successData.local_part}-${this.domain}-recovery.txt`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    }
  },
  beforeUnmount() {
    clearTimeout(this.searchTimer)
    if (this.paymentChecker) clearInterval(this.paymentChecker)
  },
  created() {
    if (this.form.local_part) {
      this.scheduleAvailabilityCheck(0)
    }
  }
})
