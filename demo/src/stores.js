// In-memory libsignal stores for one device.
import * as S from '@signalapp/libsignal-client'

const k = (a) => `${a.name()}.${a.deviceId()}`

export class Stores {
  constructor(identity, registrationId, { onPreKeyRemoved, onIdentityChanged } = {}) {
    this.identity = identity
    this.registrationId = registrationId
    const sessions = new Map(), identities = new Map(), preKeys = new Map()
    const signed = new Map(), kyber = new Map(), senderKeys = new Map()

    this.session = new (class extends S.SessionStore {
      async saveSession(a, r) { sessions.set(k(a), r.serialize()) }
      async getSession(a) { const b = sessions.get(k(a)); return b ? S.SessionRecord.deserialize(b) : null }
      async getExistingSessions(as) { return Promise.all(as.map((a) => this.getSession(a))) }
    })()

    this.identityStore = new (class extends S.IdentityKeyStore {
      async getIdentityKey() { return identity.privateKey }
      async getLocalRegistrationId() { return registrationId }
      async saveIdentity(a, key) {
        const old = identities.get(a.name())
        identities.set(a.name(), key)
        if (old && !old.equals(key)) { onIdentityChanged?.(a.name()); return S.IdentityChange.ReplacedExisting }
        return S.IdentityChange.NewOrUnchanged
      }
      // Trust on first use; a changed key is refused until re-verified out of band.
      async isTrustedIdentity(a, key) { const old = identities.get(a.name()); return !old || old.equals(key) }
      async getIdentity(a) { return identities.get(a.name()) ?? null }
    })()

    this.preKey = new (class extends S.PreKeyStore {
      async savePreKey(id, r) { preKeys.set(id, r) }
      async getPreKey(id) { const r = preKeys.get(id); if (!r) throw new Error(`no prekey ${id}`); return r }
      async removePreKey(id) { preKeys.delete(id); onPreKeyRemoved?.(id) }
    })()

    this.signedPreKey = new (class extends S.SignedPreKeyStore {
      async saveSignedPreKey(id, r) { signed.set(id, r) }
      async getSignedPreKey(id) { return signed.get(id) }
    })()

    this.kyberPreKey = new (class extends S.KyberPreKeyStore {
      async saveKyberPreKey(id, r) { kyber.set(id, r) }
      async getKyberPreKey(id) { return kyber.get(id) }
      async markKyberPreKeyUsed() {} // last-resort key: kept
    })()

    this.senderKey = new (class extends S.SenderKeyStore {
      async saveSenderKey(a, dist, r) { senderKeys.set(`${k(a)}/${dist}`, r.serialize()) }
      async getSenderKey(a, dist) { const b = senderKeys.get(`${k(a)}/${dist}`); return b ? S.SenderKeyRecord.deserialize(b) : null }
    })()
  }
}
