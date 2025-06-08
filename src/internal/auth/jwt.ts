import * as crypto from 'node:crypto'
import jwt from 'jsonwebtoken'
import { ERRORS } from '@internal/errors'

import { getConfig, JwksConfig, JwksConfigKey, JwksConfigKeyOCT } from '../../config'

const { jwtAlgorithm } = getConfig()

const JWT_HMAC_ALGOS: jwt.Algorithm[] = ['HS256', 'HS384', 'HS512']
const JWT_RSA_ALGOS: jwt.Algorithm[] = ['RS256', 'RS384', 'RS512']
const JWT_ECC_ALGOS: jwt.Algorithm[] = ['ES256', 'ES384', 'ES512']
const JWT_ED_ALGOS: jwt.Algorithm[] = ['EdDSA'] as unknown as jwt.Algorithm[] // types for EdDSA not yet updated

export type SignedToken = {
  url: string
  transformations?: string
  exp: number
}

export type SignedUploadToken = {
  owner: string | undefined
  upsert: boolean
  url: string
  exp: number
}

export function findJWKFromHeader(header: jwt.JwtHeader, secret: string, jwks: JwksConfig | null) {
  if (!jwks || !jwks.keys) {
    return secret
  }

  if (JWT_HMAC_ALGOS.indexOf(header.alg as jwt.Algorithm) > -1) {
    // JWT is using HS, find the proper key

    if (!header.kid && header.alg === jwtAlgorithm) {
      // jwt is probably signed with the static secret
      return secret
    }

    // find the first key without a kid or with the matching kid and the "oct" type
    const jwk = jwks.keys.find(
      (key) => (!key.kid || key.kid === header.kid) && key.kty === 'oct' && key.k
    )

    if (!jwk) {
      // jwt is probably signed with the static secret
      return secret
    }

    return Buffer.from(jwk.k, 'base64')
  }

  // jwt is using an asymmetric algorithm
  let kty = 'RSA'

  if (JWT_ECC_ALGOS.indexOf(header.alg as jwt.Algorithm) > -1) {
    kty = 'EC'
  } else if (JWT_ED_ALGOS.indexOf(header.alg as jwt.Algorithm) > -1) {
    kty = 'OKP'
  }

  // find the first key with a matching kid (or no kid if none is specified in the JWT header) and the correct key type
  const jwk = jwks.keys.find((key) => {
    return ((!key.kid && !header.kid) || key.kid === header.kid) && key.kty === kty
  })

  if (!jwk) {
    // couldn't find a matching JWK, try to use the secret
    return secret
  }

  return crypto.createPublicKey({
    format: 'jwk',
    key: jwk as crypto.JsonWebKey,
  })
}

function getJWTVerificationKey(secret: string, jwks: JwksConfig | null): jwt.GetPublicKeyOrSecret {
  return (header: jwt.JwtHeader, callback: jwt.SigningKeyCallback) => {
    let result: jwt.Secret | null = null

    try {
      result = findJWKFromHeader(header, secret, jwks)
    } catch (e) {
      callback(e as Error)
      return
    }

    callback(null, result)
  }
}

export function getJWTAlgorithms(jwks: JwksConfig | null) {
  let algorithms: jwt.Algorithm[]

  if (jwks && jwks.keys && jwks.keys.length) {
    const hasRSA = jwks.keys.find((key) => key.kty === 'RSA')
    const hasECC = jwks.keys.find((key) => key.kty === 'EC')
    const hasED = jwks.keys.find(
      (key) => key.kty === 'OKP' && (key.crv === 'Ed25519' || key.crv === 'Ed448')
    )
    const hasHS = jwks.keys.find((key) => key.kty === 'oct' && key.k)

    algorithms = [
      jwtAlgorithm as jwt.Algorithm,
      ...(hasRSA ? JWT_RSA_ALGOS : []),
      ...(hasECC ? JWT_ECC_ALGOS : []),
      ...(hasED ? JWT_ED_ALGOS : []),
      ...(hasHS ? JWT_HMAC_ALGOS : []),
    ]
  } else {
    algorithms = [jwtAlgorithm as jwt.Algorithm]
  }

  return algorithms
}

/**
 * Verifies if a JWT is valid
 * @param token
 * @param secret
 * @param jwks
 */
export function verifyJWT<T>(
  token: string,
  secret: string,
  jwks?: { keys: JwksConfigKey[] } | null
): Promise<jwt.JwtPayload & T> {
  return new Promise((resolve, reject) => {
    jwt.verify(
      token,
      getJWTVerificationKey(secret, jwks || null),
      { algorithms: getJWTAlgorithms(jwks || null) },
      (err, decoded) => {
        if (err) return reject(ERRORS.AccessDenied(err.message, err))
        resolve(decoded as jwt.JwtPayload & T)
      }
    )
  })
}
/**
 * Verify and decode a JWT token used for storage URL signing
 * @param token - The JWT token string to verify and decode
 */

export function verifyStorageUrlToken<T>(token: string): Promise<jwt.JwtPayload & T> {
  const { URL_SIGNING_SECRET, URL_SIGNING_ALGORITHM } = getConfig()

  if (!URL_SIGNING_SECRET) {
    return Promise.reject(new Error('URL_SIGNING_SECRET is not configured for verification.'))
  }
  if (!URL_SIGNING_ALGORITHM) {
    return Promise.reject(new Error('URL_SIGNING_ALGORITHM is not configured for verification.'))
  }

  return new Promise<jwt.JwtPayload & T>((resolve, reject) => {
    jwt.verify(
      token,
      URL_SIGNING_SECRET,
      { algorithms: [URL_SIGNING_ALGORITHM as jwt.Algorithm] }, // Must match what signStorageUrlToken (or modified signJWT) used
      (err, decoded) => {
        if (err) {
          if (err.name === 'TokenExpiredError') {
            return reject(ERRORS.ExpiredSignature(err))
          }
          if (err.name === 'JsonWebTokenError') {
            // This includes "invalid algorithm"
            return reject(ERRORS.InvalidJWT(err))
          }
          return reject(err)
        }
        resolve(decoded as jwt.JwtPayload & T)
      }
    )
  })
}

/**
 * Sign a JWT
 * @param payload
 * @param secret
 * @param expiresIn
 */
export function signJWT(
  payload: string | object | Buffer,
  secret: string | JwksConfigKeyOCT,
  expiresIn: string | number | undefined
): Promise<string> {
  const options: jwt.SignOptions = { algorithm: jwtAlgorithm as jwt.Algorithm }

  let signingSecret: string | Buffer = typeof secret === 'string' ? secret : ''
  if (typeof secret === 'object' && secret?.kid && secret?.k) {
    options.keyid = secret.kid
    if (secret.alg) {
      options.algorithm = secret.alg as jwt.Algorithm
    }
    signingSecret = Buffer.from(secret.k, 'base64')
  }

  if (expiresIn) {
    options.expiresIn = expiresIn
  }

  return new Promise<string>((resolve, reject) => {
    jwt.sign(payload, signingSecret, options, (err, token) => {
      if (err) return reject(err)
      resolve(token as string)
    })
  })
}

/**
 * Signs a token specifically for Supabase Storage pre-signed URLs.
 * Uses URL_SIGNING_SECRET and URL_SIGNING_ALGORITHM from environment variables.
 *
 * @param payload The data to include in the JWT.
 * @param expiresIn The expiration time for the JWT (e.g., "1h", "7d", or number of seconds).
 */
export function signStorageUrlToken(
  payload: string | object | Buffer,
  expiresIn: string | number | undefined
): Promise<string> {
  const { URL_SIGNING_SECRET, URL_SIGNING_ALGORITHM } = getConfig() // Get the new env vars

  if (!URL_SIGNING_SECRET) {
    return Promise.reject(new Error('URL_SIGNING_SECRET is not configured.'))
  }
  if (!URL_SIGNING_ALGORITHM) {
    return Promise.reject(new Error('URL_SIGNING_ALGORITHM is not configured.'))
  }

  const options: jwt.SignOptions = {
    algorithm: URL_SIGNING_ALGORITHM as jwt.Algorithm,
  }

  if (expiresIn) {
    options.expiresIn = expiresIn
  }

  // The URL_SIGNING_SECRET is expected to be a simple string (symmetric key)
  const signingSecret: string | Buffer = URL_SIGNING_SECRET

  return new Promise<string>((resolve, reject) => {
    jwt.sign(payload, signingSecret, options, (err, token) => {
      if (err) {
        // Log the specific error for better debugging
        console.error(
          'Error signing storage URL token:',
          err.message,
          'Algorithm:',
          options.algorithm
        )
        return reject(err)
      }
      resolve(token as string)
    })
  })
}

/**
 * Generate a new random HS256 JWK that can be used for signing JWTs
 */
export function generateHS256JWK(): JwksConfigKeyOCT {
  // Generate a 64-byte random key, convert the secret key to Base64URL encoding (JWK standard)
  const k = crypto.randomBytes(64).toString('base64url')
  return { kty: 'oct', alg: 'HS256', k }
}
