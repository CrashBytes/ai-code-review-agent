#!/usr/bin/env node

const { Anthropic } = require('@anthropic-ai/sdk');
const { Octokit } = require('@octokit/rest');
const fs = require('fs').promises;
const crypto = require('crypto');

class CodeReviewAgent {
  constructor() {
    this.anthropic = new Anthropic({
      apiKey: process.env.ANTHROPIC_API_KEY,
    });
    
    this.github = new Octokit({
      auth: process.env.GITHUB_TOKEN,
    });
    
    this.config = this.loadConfiguration();
    this.monitoring = new MonitoringService();
    this.security = new SecurityValidator();
  }
  
  loadConfiguration() {
    const defaultConfig = {
      model: 'claude-sonnet-4-20250514',
      maxTokens: 4000,
      temperature: 0.0,
      reviewFocus: [
        'security-vulnerabilities',
        'code-quality',
        'architectural-concerns',
        'performance-issues',
        'error-handling'
      ],
      excludePatterns: [
        '**/node_modules/**',
        '**/dist/**',
        '**/build/**',
        '**/*.test.js',
        '**/*.spec.js'
      ],
      minSeverity: 'medium'
    };
    
    try {
      const customConfig = require('../.ai-review-config.json');
      return { ...defaultConfig, ...customConfig };
    } catch (error) {
      return defaultConfig;
    }
  }
  
  async execute() {
    try {
      this.security.validateAPIKey(process.env.ANTHROPIC_API_KEY);
      this.security.validateGitHubToken(process.env.GITHUB_TOKEN);
      
      const context = await this.gatherContext();
      const changedFiles = await this.getChangedFiles(context);
      const filteredFiles = this.filterRelevantFiles(changedFiles);
      
      if (filteredFiles.length === 0) {
        console.log('No relevant files to review');
        return;
      }
      
      const reviewResults = await this.analyzeChanges(
        filteredFiles, 
        context
      );
      
      await this.postReviewComments(reviewResults, context);
      
      console.log(`Review complete: ${reviewResults.findings.length} findings`);
      this.monitoring.logToGitHubActions();
      
    } catch (error) {
      this.monitoring.recordError(error);
      this.monitoring.logToGitHubActions();
      throw error;
    }
  }
  
  async gatherContext() {
    const eventPath = process.env.GITHUB_EVENT_PATH;
    const event = JSON.parse(await fs.readFile(eventPath, 'utf8'));
    
    const context = {
      owner: event.repository.owner.login,
      repo: event.repository.name,
      prNumber: event.pull_request.number,
      prTitle: event.pull_request.title,
      prDescription: event.pull_request.body || '',
      author: event.pull_request.user.login,
      baseBranch: event.pull_request.base.ref,
      headBranch: event.pull_request.head.ref,
      baseSha: event.pull_request.base.sha,
      headSha: event.pull_request.head.sha
    };
    
    context.prContext = this.analyzePRIntent(context);
    
    return context;
  }
  
  analyzePRIntent(context) {
    const title = context.prTitle.toLowerCase();
    const description = context.prDescription.toLowerCase();
    const combined = `${title} ${description}`;
    
    const intent = {
      isBugFix: /fix|bug|issue|error|crash/i.test(combined),
      isFeature: /feature|add|implement|new/i.test(combined),
      isRefactor: /refactor|cleanup|improve|optimize/i.test(combined),
      isSecurity: /security|vulnerability|cve|exploit/i.test(combined),
      isBreaking: /breaking|major|incompatible/i.test(combined),
      isDocs: /docs|documentation|readme/i.test(combined)
    };
    
    return intent;
  }
  
  async getChangedFiles(context) {
    const { owner, repo, prNumber } = context;
    
    const { data: files } = await this.github.pulls.listFiles({
      owner,
      repo,
      pull_number: prNumber,
      per_page: 100
    });
    
    const enrichedFiles = await Promise.all(
      files.map(async file => {
        const content = await this.fetchFileContent(
          owner, 
          repo, 
          file.filename,
          context.headSha
        );
        
        return {
          filename: file.filename,
          status: file.status,
          additions: file.additions,
          deletions: file.deletions,
          changes: file.changes,
          patch: file.patch,
          content: content,
          extension: this.getFileExtension(file.filename),
          language: this.detectLanguage(file.filename)
        };
      })
    );
    
    return enrichedFiles;
  }
  
  async fetchFileContent(owner, repo, path, ref) {
    try {
      const { data } = await this.github.repos.getContent({
        owner,
        repo,
        path,
        ref
      });
      
      if (data.type !== 'file') return null;
      
      const content = Buffer.from(data.content, 'base64').toString('utf8');
      
      this.security.validateFileSize(content);
      
      return content;
    } catch (error) {
      console.warn(`Could not fetch ${path}:`, error.message);
      return null;
    }
  }
  
  getFileExtension(filename) {
    return filename.split('.').pop().toLowerCase();
  }
  
  detectLanguage(filename) {
    const extensionMap = {
      js: 'JavaScript',
      ts: 'TypeScript',
      jsx: 'React',
      tsx: 'React TypeScript',
      py: 'Python',
      java: 'Java',
      go: 'Go',
      rs: 'Rust',
      rb: 'Ruby',
      php: 'PHP',
      cs: 'C#',
      cpp: 'C++',
      c: 'C',
      sql: 'SQL',
      sh: 'Shell',
      yaml: 'YAML',
      yml: 'YAML',
      json: 'JSON',
      md: 'Markdown'
    };
    
    const ext = this.getFileExtension(filename);
    return extensionMap[ext] || 'Unknown';
  }
  
  filterRelevantFiles(files) {
    const isExcluded = (filename) => {
      return this.config.excludePatterns.some(pattern => {
        const regex = new RegExp(
          pattern
            .replace(/\*\*/g, '.*')
            .replace(/\*/g, '[^/]*')
        );
        return regex.test(filename);
      });
    };
    
    return files.filter(file => {
      if (isExcluded(file.filename)) return false;
      if (file.status === 'removed') return false;
      if (!file.patch && file.status !== 'added') return false;
      if (file.changes === 0) return false;
      
      return true;
    });
  }
  
  async analyzeChanges(files, context) {
    const chunks = this.chunkFiles(files);
    
    const allFindings = [];
    
    for (const chunk of chunks) {
      const prompt = this.buildReviewPrompt(chunk, context);
      
      const tokenEstimate = this.estimateTokens(prompt);
      
      const response = await this.anthropic.messages.create({
        model: this.config.model,
        max_tokens: this.config.maxTokens,
        temperature: this.config.temperature,
        messages: [{
          role: 'user',
          content: prompt
        }]
      });
      
      this.monitoring.recordAPICall(tokenEstimate);
      
      const findings = this.parseReviewResponse(
        response.content[0].text,
        chunk
      );
      
      findings.forEach(f => this.monitoring.recordFinding(f));
      
      allFindings.push(...findings);
    }
    
    return {
      findings: this.deduplicateFindings(allFindings),
      reviewedFiles: files.length,
      totalFindings: allFindings.length
    };
  }
  
  chunkFiles(files) {
    const chunks = [];
    let currentChunk = [];
    let currentTokens = 0;
    const maxTokensPerChunk = 15000;
    
    for (const file of files) {
      const fileTokens = this.estimateTokens(
        (file.patch || '') + (file.content || '')
      );
      
      if (currentTokens + fileTokens > maxTokensPerChunk && currentChunk.length > 0) {
        chunks.push(currentChunk);
        currentChunk = [];
        currentTokens = 0;
      }
      
      currentChunk.push(file);
      currentTokens += fileTokens;
    }
    
    if (currentChunk.length > 0) {
      chunks.push(currentChunk);
    }
    
    return chunks;
  }
  
  estimateTokens(text) {
    return Math.ceil(text.length / 4);
  }
  
  buildReviewPrompt(files, context) {
    const { prContext } = context;
    
    const intentContext = Object.entries(prContext)
      .filter(([_, value]) => value)
      .map(([key, _]) => key.replace('is', ''))
      .join(', ');
    
    const filesContext = files.map(file => `
File: ${file.filename} (${file.language})
Status: ${file.status}
Changes: +${file.additions} -${file.deletions}

Diff:
${file.patch || 'New file - full content below'}

${file.content ? `Full content:\n${file.content.slice(0, 5000)}` : ''}
`).join('\n---\n');

    return `You are a senior software engineer conducting a code review for a pull request.

PR Context:
- Title: ${context.prTitle}
- Author: ${context.author}
- Intent: ${intentContext || 'general code change'}
- Target branch: ${context.baseBranch}

Review Focus Areas:
${this.config.reviewFocus.map(focus => `- ${focus}`).join('\n')}

Files to Review:
${filesContext}

Provide a structured code review focusing on:

1. **Security Vulnerabilities**: SQL injection, XSS, authentication bypasses, cryptographic issues, input validation problems
2. **Code Quality**: Code duplication, overly complex logic, poor naming, missing error handling, magic numbers
3. **Architectural Concerns**: Violation of SOLID principles, tight coupling, missing abstractions, scalability issues
4. **Performance Issues**: N+1 queries, inefficient algorithms, unnecessary computations, memory leaks
5. **Error Handling**: Missing try-catch blocks, unhandled promise rejections, silent failures

For each finding, provide:
- **Severity**: critical, high, medium, low
- **Category**: security, quality, architecture, performance, error-handling
- **File**: exact filename
- **Line**: line number if applicable
- **Issue**: clear description of the problem
- **Recommendation**: specific actionable fix
- **Example**: code snippet showing the fix if helpful

Format your response as JSON:
{
  "findings": [
    {
      "severity": "high",
      "category": "security",
      "file": "src/auth.js",
      "line": 42,
      "issue": "SQL injection vulnerability due to string concatenation",
      "recommendation": "Use parameterized queries with prepared statements",
      "example": "const query = 'SELECT * FROM users WHERE id = ?'; db.query(query, [userId]);"
    }
  ]
}

Only include findings at ${this.config.minSeverity} severity or higher. Be specific and actionable.`;
  }
  
  parseReviewResponse(responseText, files) {
    try {
      const jsonMatch = responseText.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        console.warn('No JSON found in response');
        return [];
      }
      
      const parsed = JSON.parse(jsonMatch[0]);
      
      if (!parsed.findings || !Array.isArray(parsed.findings)) {
        console.warn('Invalid response format');
        return [];
      }
      
      return parsed.findings.map(finding => ({
        ...finding,
        id: this.generateFindingId(finding),
        timestamp: new Date().toISOString()
      }));
    } catch (error) {
      console.error('Failed to parse review response:', error);
      this.monitoring.recordError(error);
      return [];
    }
  }
  
  generateFindingId(finding) {
    const components = [
      finding.file,
      finding.line || 0,
      finding.category,
      finding.issue.slice(0, 50)
    ].join('|');
    
    return crypto
      .createHash('sha256')
      .update(components)
      .digest('hex')
      .slice(0, 16);
  }
  
  deduplicateFindings(findings) {
    const seen = new Set();
    
    return findings.filter(finding => {
      if (seen.has(finding.id)) {
        return false;
      }
      seen.add(finding.id);
      return true;
    });
  }
  
  async postReviewComments(reviewResults, context) {
    const { findings } = reviewResults;
    
    const existingComments = await this.getExistingComments(context);
    
    const newFindings = this.filterNewFindings(
      findings,
      existingComments
    );
    
    if (newFindings.length === 0) {
      console.log('No new findings to post');
      return;
    }
    
    const groupedFindings = this.groupFindingsByFile(newFindings);
    
    for (const [filename, fileFindings] of Object.entries(groupedFindings)) {
      await this.postFileReview(
        filename,
        fileFindings,
        context
      );
    }
  }
  
  async getExistingComments(context) {
    const { owner, repo, prNumber } = context;
    
    const { data: comments } = await this.github.pulls.listReviewComments({
      owner,
      repo,
      pull_number: prNumber,
      per_page: 100
    });
    
    return comments.filter(comment => 
      comment.body.includes('AI Code Review')
    );
  }
  
  filterNewFindings(findings, existingComments) {
    const existingIds = new Set(
      existingComments
        .map(comment => {
          const match = comment.body.match(/Finding ID: ([a-f0-9]+)/);
          return match ? match[1] : null;
        })
        .filter(Boolean)
    );
    
    return findings.filter(finding => 
      !existingIds.has(finding.id)
    );
  }
  
  groupFindingsByFile(findings) {
    const grouped = {};
    
    for (const finding of findings) {
      if (!grouped[finding.file]) {
        grouped[finding.file] = [];
      }
      grouped[finding.file].push(finding);
    }
    
    return grouped;
  }
  
  async postFileReview(filename, findings, context) {
    const { owner, repo, prNumber, headSha } = context;
    
    const sortedFindings = findings.sort((a, b) => {
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      return severityOrder[a.severity] - severityOrder[b.severity];
    });
    
    for (const finding of sortedFindings) {
      const commentBody = this.formatFindingComment(finding);
      
      try {
        await this.github.pulls.createReviewComment({
          owner,
          repo,
          pull_number: prNumber,
          commit_id: headSha,
          path: filename,
          line: finding.line || 1,
          side: 'RIGHT',
          body: commentBody
        });
        
        this.monitoring.recordComment();
        
        await this.sleep(1000);
        
      } catch (error) {
        if (error.status === 422) {
          console.warn(`Could not comment on ${filename}:${finding.line}:`, error.message);
        } else {
          throw error;
        }
      }
    }
  }
  
  formatFindingComment(finding) {
    const severityEmoji = {
      critical: '🔴',
      high: '🟠',
      medium: '🟡',
      low: '🟢'
    };
    
    const icon = severityEmoji[finding.severity] || '⚪';
    
    let comment = `### AI Code Review ${icon} ${finding.severity.toUpperCase()}\n\n`;
    comment += `**Category**: ${finding.category}\n\n`;
    comment += `**Issue**: ${finding.issue}\n\n`;
    comment += `**Recommendation**: ${finding.recommendation}\n\n`;
    
    if (finding.example) {
      comment += `**Example Fix**:\n\`\`\`${this.detectLanguageFromFile(finding.file)}\n`;
      comment += `${finding.example}\n`;
      comment += `\`\`\`\n\n`;
    }
    
    comment += `---\n`;
    comment += `*Finding ID: ${finding.id}*\n`;
    comment += `*Generated by AI Code Review Agent*`;
    
    return comment;
  }
  
  detectLanguageFromFile(filename) {
    const ext = filename.split('.').pop().toLowerCase();
    const langMap = {
      js: 'javascript',
      ts: 'typescript',
      jsx: 'jsx',
      tsx: 'tsx',
      py: 'python',
      java: 'java',
      go: 'go',
      rs: 'rust',
      rb: 'ruby',
      php: 'php'
    };
    
    return langMap[ext] || '';
  }
  
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

class SecurityValidator {
  validateAPIKey(apiKey) {
    if (!apiKey || typeof apiKey !== 'string') {
      throw new Error('ANTHROPIC_API_KEY environment variable required');
    }
    
    if (!apiKey.startsWith('sk-ant-')) {
      throw new Error('Invalid Anthropic API key format');
    }
    
    if (apiKey.length < 50) {
      throw new Error('API key appears truncated or invalid');
    }
  }
  
  validateGitHubToken(token) {
    if (!token || typeof token !== 'string') {
      throw new Error('GITHUB_TOKEN environment variable required');
    }
    
    if (token.length < 20) {
      throw new Error('GitHub token appears invalid');
    }
  }
  
  validateFileSize(content, maxSize = 1000000) {
    if (content && content.length > maxSize) {
      throw new Error(`File content exceeds ${maxSize} bytes`);
    }
  }
}

class MonitoringService {
  constructor() {
    this.metrics = {
      executionStart: Date.now(),
      apiCalls: 0,
      tokensUsed: 0,
      findingsGenerated: 0,
      commentsPosted: 0,
      errors: []
    };
  }
  
  recordAPICall(tokens) {
    this.metrics.apiCalls++;
    this.metrics.tokensUsed += tokens;
  }
  
  recordFinding(finding) {
    this.metrics.findingsGenerated++;
  }
  
  recordComment() {
    this.metrics.commentsPosted++;
  }
  
  recordError(error) {
    this.metrics.errors.push({
      message: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString()
    });
  }
  
  generateSummary() {
    const executionTime = Date.now() - this.metrics.executionStart;
    
    return {
      ...this.metrics,
      executionTimeMs: executionTime,
      executionTimeSec: Math.round(executionTime / 1000),
      costEstimate: this.estimateCost()
    };
  }
  
  estimateCost() {
    const inputCost = 0.003;
    const outputCost = 0.015;
    const estimatedOutputTokens = this.metrics.tokensUsed * 0.3;
    
    const cost = (this.metrics.tokensUsed * inputCost / 1000) +
                 (estimatedOutputTokens * outputCost / 1000);
    
    return Math.round(cost * 100) / 100;
  }
  
  logToGitHubActions() {
    const summary = this.generateSummary();
    
    console.log('::group::Review Metrics');
    console.log(`Execution Time: ${summary.executionTimeSec}s`);
    console.log(`API Calls: ${summary.apiCalls}`);
    console.log(`Tokens Used: ${summary.tokensUsed}`);
    console.log(`Findings: ${summary.findingsGenerated}`);
    console.log(`Comments Posted: ${summary.commentsPosted}`);
    console.log(`Estimated Cost: $${summary.costEstimate}`);
    console.log('::endgroup::');
    
    if (summary.errors.length > 0) {
      console.log('::group::Errors');
      summary.errors.forEach(err => {
        console.error(`${err.timestamp}: ${err.message}`);
      });
      console.log('::endgroup::');
    }
  }
}

async function main() {
  const agent = new CodeReviewAgent();
  await agent.execute();
}

main().catch(error => {
  console.error('Review failed:', error);
  process.exit(1);
});

module.exports = { CodeReviewAgent, SecurityValidator, MonitoringService };
