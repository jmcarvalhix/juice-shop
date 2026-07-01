/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { type Review } from '../data/types'
import * as db from '../data/mongodb'

const sleep = async (ms: number) => await new Promise(resolve => setTimeout(resolve, ms))

/*
  CORREÇÃO DE SEGURANÇA (CWE-943): NoSQL Injection

  1. Problema: O código original ('req.body.id') aceitava objetos do utilizador.
  2. Risco: Um atacante (via Burp Suite) podia injetar operadores como '{"$ne": "11111111"}'.
     O MongoDB avalia as duas partes (chave e valor) como uma instrução lógica em vez de um ID.
  3. Solução: Aplicado o método 'String()' para forçar o dado a ser uma cadeia de caracteres pura.
  4. Resultado: Destrói a estrutura do objeto, convertendo-o no texto inofensivo "[object Object]".
     A consulta falha de forma segura (404) porque o MongoDB deixa de conseguir ler as duas partes.
  
  Nota:
  Esta alteração mitiga a vulnerabilidade. Numa aplicação de produção, a abordagem
  recomendada passa também pela validação do tipo, formato e conteúdo
  dos dados recebidos antes de qualquer acesso à base de dados.
*/

export function likeProductReviews () {
  return async (req: Request, res: Response, next: NextFunction) => {
    //const id = req.body.id
    const id = String(req.body.id);
    const user = security.authenticatedUsers.from(req)
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' })
    }

    try {
      const review = await db.reviewsCollection.findOne({ _id: id })
      if (!review) {
        return res.status(404).json({ error: 'Not found' })
      }

      const likedBy = review.likedBy
      if (likedBy.includes(user.data.email)) {
        return res.status(403).json({ error: 'Not allowed' })
      }

      await db.reviewsCollection.update(
        { _id: id },
        { $inc: { likesCount: 1 } }
      )

      // Artificial wait for timing attack challenge
      await sleep(150)
      try {
        const updatedReview: Review = await db.reviewsCollection.findOne({ _id: id })
        const updatedLikedBy = updatedReview.likedBy
        updatedLikedBy.push(user.data.email)

        const count = updatedLikedBy.filter(email => email === user.data.email).length
        challengeUtils.solveIf(challenges.timingAttackChallenge, () => count > 2)

        const result = await db.reviewsCollection.update(
          { _id: id },
          { $set: { likedBy: updatedLikedBy } }
        )
        res.json(result)
      } catch (err) {
        res.status(500).json(err)
      }
    } catch (err) {
      res.status(400).json({ error: 'Wrong Params' })
    }
  }
}
