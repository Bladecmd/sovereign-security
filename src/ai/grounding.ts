/**
 * Sovereign Security — Milestone V0.6
 * Semantic Grounding & Hallucination Guard
 */

import { GroundingCheckRequest, GroundingCheckResult } from '../types/ai-gateway.js';

export class SemanticGroundingGuard {
  private defaultThreshold: number;

  constructor(defaultThreshold: number = 0.6) {
    this.defaultThreshold = defaultThreshold;
  }

  /**
   * Tokenize and normalize text into meaningful term tokens (excluding common stop words)
   */
  private extractKeyTerms(text: string): Set<string> {
    const stopWords = new Set([
      'the', 'is', 'at', 'which', 'on', 'a', 'an', 'and', 'or', 'in', 'to', 'for', 'of', 'with',
      'as', 'by', 'that', 'it', 'from', 'be', 'are', 'was', 'were', 'has', 'have', 'had', 'been',
      'this', 'these', 'those', 'we', 'they', 'i', 'you', 'he', 'she', 'its', 'our', 'their',
    ]);

    const words = text
      .toLowerCase()
      .replace(/[^\w\s]/g, ' ')
      .split(/\s+/)
      .filter((w) => w.length > 2 && !stopWords.has(w));

    return new Set(words);
  }

  /**
   * Breaks paragraph into distinct declarative statements / sentences
   */
  private splitIntoStatements(text: string): string[] {
    return text
      .split(/(?<=[.!?])\s+|\n+/)
      .map((s) => s.trim())
      .filter((s) => s.length > 5);
  }

  /**
   * Evaluates whether a claim is grounded in the provided source context documents
   */
  public verifyGrounding(request: GroundingCheckRequest): GroundingCheckResult {
    const threshold = request.minimumGroundingScore ?? this.defaultThreshold;
    const statements = this.splitIntoStatements(request.claim);

    if (statements.length === 0) {
      return {
        grounded: true,
        score: 1.0,
        unsupportedStatements: [],
        supportedStatements: [],
        confidence: 1.0,
      };
    }

    // Combine all source context documents into unified term vocabulary
    const combinedSourceText = request.sourceContexts.join(' ');
    const sourceTerms = this.extractKeyTerms(combinedSourceText);

    const supportedStatements: string[] = [];
    const unsupportedStatements: string[] = [];
    let statementScoreSum = 0;

    for (const statement of statements) {
      const statementTerms = this.extractKeyTerms(statement);
      if (statementTerms.size === 0) {
        supportedStatements.push(statement);
        statementScoreSum += 1.0;
        continue;
      }

      let matchedTerms = 0;
      for (const term of statementTerms) {
        if (sourceTerms.has(term)) {
          matchedTerms++;
        }
      }

      const statementScore = matchedTerms / statementTerms.size;
      statementScoreSum += statementScore;

      if (statementScore >= threshold) {
        supportedStatements.push(statement);
      } else {
        unsupportedStatements.push(statement);
      }
    }

    const overallScore = Math.round((statementScoreSum / statements.length) * 100) / 100;
    const grounded = unsupportedStatements.length === 0 && overallScore >= threshold;

    return {
      grounded,
      score: overallScore,
      unsupportedStatements,
      supportedStatements,
      confidence: 0.9,
    };
  }
}
