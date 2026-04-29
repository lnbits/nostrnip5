const NPUB_REGEX = /^npub1[023456789acdefghjklmnpqrstuvwxyz]{58,}$/
const HEX_REGEX = /^[0-9a-f]{64}$/i

function classifyPubkey(value) {
  if (!value) return 'empty'
  if (NPUB_REGEX.test(value)) return 'npub'
  if (HEX_REGEX.test(value)) return 'hex'
  return 'invalid'
}

window.app = Vue.createApp({
  el: '#vue',
  mixins: [window.windowMixin],
  data() {
    return {
      domain,
      domain_id,
      address_id,
      handle: `${localPart}@${domain}`,
      currentPubkey,
      secretFromUrl: Boolean(secret),
      form: {
        pubkey: '',
        secret: secret || ''
      },
      submitting: false,
      done: false
    }
  },
  computed: {
    pubkeyState() {
      return classifyPubkey(this.form.pubkey)
    },
    canSubmit() {
      const valid = this.pubkeyState === 'npub' || this.pubkeyState === 'hex'
      return valid && Boolean(this.form.secret) && !this.submitting
    }
  },
  methods: {
    truncate(value, head = 12, tail = 6) {
      if (!value) return ''
      if (value.length <= head + tail + 1) return value
      return `${value.slice(0, head)}…${value.slice(-tail)}`
    },
    async pasteFromClipboard() {
      try {
        const text = await navigator.clipboard.readText()
        this.form.pubkey = (text || '').trim()
      } catch (e) {
        this.$q.notify({type: 'warning', message: 'Clipboard access denied'})
      }
    },
    rotateKey() {
      if (!this.canSubmit) return
      this.submitting = true
      axios
        .put(
          `/nostrnip5/api/v1/domain/${this.domain_id}/address/${this.address_id}/rotate`,
          {pubkey: this.form.pubkey, secret: this.form.secret}
        )
        .then(() => {
          this.done = true
          this.$q.notify({
            type: 'positive',
            message: 'Your public key has been updated.'
          })
        })
        .catch(LNbits.utils.notifyApiError)
        .finally(() => {
          this.submitting = false
        })
    }
  }
})
