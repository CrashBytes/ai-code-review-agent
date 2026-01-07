const { expect } = require('chai');
const sinon = require('sinon');
const { CodeReviewAgent } = require('../src/review-agent');

describe('CodeReviewAgent', () => {
  let agent;
  let anthropicStub;
  let githubStub;
  
  beforeEach(() => {
    anthropicStub = {
      messages: {
        create: sinon.stub()
      }
    };
    
    githubStub = {
      pulls: {
        listFiles: sinon.stub(),
        listReviewComments: sinon.stub(),
        createReviewComment: sinon.stub()
      },
      repos: {
        getContent: sinon.stub()
      }
    };
    
    agent = new CodeReviewAgent();
    agent.anthropic = anthropicStub;
    agent.github = githubStub;
  });
  
  describe('chunkFiles', () => {
    it('splits large file sets into manageable chunks', () => {
      const files = Array(100).fill({
        filename: 'test.js',
        patch: 'x'.repeat(1000),
        content: 'x'.repeat(5000)
      });
      
      const chunks = agent.chunkFiles(files);
      
      expect(chunks.length).to.be.greaterThan(1);
      chunks.forEach(chunk => {
        const totalTokens = chunk.reduce((sum, file) => {
          return sum + agent.estimateTokens(
            file.patch + file.content
          );
        }, 0);
        expect(totalTokens).to.be.lessThan(15000);
      });
    });
    
    it('keeps small file sets in single chunk', () => {
      const files = [
        { filename: 'a.js', patch: 'small', content: 'tiny' },
        { filename: 'b.js', patch: 'small', content: 'tiny' }
      ];
      
      const chunks = agent.chunkFiles(files);
      
      expect(chunks.length).to.equal(1);
      expect(chunks[0]).to.have.lengthOf(2);
    });
  });
  
  describe('filterRelevantFiles', () => {
    it('excludes node_modules', () => {
      const files = [
        { filename: 'src/app.js', status: 'modified', changes: 10, patch: 'diff' },
        { filename: 'node_modules/package/index.js', status: 'modified', changes: 5, patch: 'diff' }
      ];
      
      const filtered = agent.filterRelevantFiles(files);
      
      expect(filtered).to.have.lengthOf(1);
      expect(filtered[0].filename).to.equal('src/app.js');
    });
    
    it('excludes removed files', () => {
      const files = [
        { filename: 'deleted.js', status: 'removed', changes: 0 },
        { filename: 'modified.js', status: 'modified', changes: 5, patch: 'diff' }
      ];
      
      const filtered = agent.filterRelevantFiles(files);
      
      expect(filtered).to.have.lengthOf(1);
      expect(filtered[0].filename).to.equal('modified.js');
    });
  });
  
  describe('analyzePRIntent', () => {
    it('detects bug fix PR', () => {
      const context = {
        prTitle: 'Fix authentication bug',
        prDescription: 'Fixes issue #123'
      };
      
      const intent = agent.analyzePRIntent(context);
      
      expect(intent.isBugFix).to.be.true;
    });
    
    it('detects security PR', () => {
      const context = {
        prTitle: 'Security patch for CVE-2025-1234',
        prDescription: 'Addresses SQL injection vulnerability'
      };
      
      const intent = agent.analyzePRIntent(context);
      
      expect(intent.isSecurity).to.be.true;
    });
    
    it('detects feature PR', () => {
      const context = {
        prTitle: 'Add user dashboard feature',
        prDescription: 'Implements new analytics dashboard'
      };
      
      const intent = agent.analyzePRIntent(context);
      
      expect(intent.isFeature).to.be.true;
    });
  });
  
  describe('parseReviewResponse', () => {
    it('extracts findings from valid JSON', () => {
      const response = JSON.stringify({
        findings: [
          {
            severity: 'high',
            category: 'security',
            file: 'auth.js',
            line: 42,
            issue: 'SQL injection',
            recommendation: 'Use parameterized queries'
          }
        ]
      });
      
      const findings = agent.parseReviewResponse(response, []);
      
      expect(findings).to.have.lengthOf(1);
      expect(findings[0].severity).to.equal('high');
      expect(findings[0].category).to.equal('security');
    });
    
    it('handles malformed JSON gracefully', () => {
      const response = 'Not JSON at all';
      
      const findings = agent.parseReviewResponse(response, []);
      
      expect(findings).to.have.lengthOf(0);
    });
  });
  
  describe('deduplicateFindings', () => {
    it('removes duplicate findings', () => {
      const findings = [
        {
          id: 'abc123',
          severity: 'high',
          issue: 'Problem A'
        },
        {
          id: 'abc123',
          severity: 'high',
          issue: 'Problem A'
        },
        {
          id: 'def456',
          severity: 'medium',
          issue: 'Problem B'
        }
      ];
      
      const deduplicated = agent.deduplicateFindings(findings);
      
      expect(deduplicated).to.have.lengthOf(2);
    });
  });
});
