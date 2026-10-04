import { useEffect, useState } from "react"

/**
 * Perfil de la cuenta (nombre y foto) para la burbuja del usuario en el dock.
 *
 * `app.js` lo publica en `window.mailmaskProfile` y avisa con `mailmask:profile` cada
 * vez que cambia (modal "Tu perfil" o Mask al terminar el turno). Si el dock monta
 * antes que eso, lo pide a `/api/profile`.
 */
export type UserProfile = { email: string; displayName: string | null; avatarUrl: string | null }

declare global {
  interface Window {
    mailmaskProfile?: UserProfile
  }
}

export function useUserProfile(): UserProfile | null {
  const [profile, setProfile] = useState<UserProfile | null>(
    typeof window !== "undefined" ? window.mailmaskProfile ?? null : null,
  )
  useEffect(() => {
    const onChange = () => setProfile(window.mailmaskProfile ?? null)
    window.addEventListener("mailmask:profile", onChange)
    if (!window.mailmaskProfile) {
      fetch("/api/profile", { credentials: "same-origin" })
        .then((r) => (r.ok ? r.json() : null))
        .then((p: UserProfile | null) => {
          if (p && !window.mailmaskProfile) setProfile(p)
        })
        .catch(() => {})
    }
    return () => window.removeEventListener("mailmask:profile", onChange)
  }, [])
  return profile
}

/** Dos iniciales del nombre, o del correo si no hay nombre. */
export function initialsOf(p: { displayName?: string | null; email?: string } | null): string {
  const base = (p?.displayName || p?.email?.split("@")[0] || "?").trim()
  const parts = base.split(/[\s._-]+/).filter(Boolean)
  const two = parts.length > 1 ? parts[0][0] + parts[1][0] : base.slice(0, 2)
  return two.toUpperCase()
}
