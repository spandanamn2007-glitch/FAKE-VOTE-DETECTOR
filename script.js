const voteDataElement = document.getElementById('vote-data');
const resultsElement = document.getElementById('results');
const runAnalysisButton = document.getElementById('run-analysis');
const loadSampleButton = document.getElementById('load-sample');

const sampleCsv = `fingerprint,voter_id,candidate,ip_address,timestamp
fp-01,1001,Alpha,192.168.1.10,2026-04-10T08:05:12Z
fp-02,1002,Beta,203.0.113.5,2026-04-10T08:07:40Z
fp-01,1003,Alpha,192.168.1.10,2026-04-10T08:09:18Z
fp-03,1004,Alpha,192.168.1.10,2026-04-10T08:10:05Z
fp-04,1005,Beta,198.51.100.23,2026-04-10T08:11:28Z
fp-02,1006,Alpha,203.0.113.5,2026-04-10T08:11:45Z
`;

loadSampleButton.addEventListener('click', () => {
  voteDataElement.value = sampleCsv;
  voteDataElement.focus();
});

runAnalysisButton.addEventListener('click', () => {
  const raw = voteDataElement.value.trim();
  if (!raw) {
    showMessage('Please paste or enter vote data in the textarea.', false);
    return;
  }

  const { rows, error } = parseCsv(raw);
  if (error) {
    showMessage(error, false);
    return;
  }

  const analysis = analyzeVotes(rows);
  renderResults(analysis);
});

function parseCsv(text) {
  const lines = text.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  if (lines.length < 2) {
    return { rows: [], error: 'Input must contain a header row and at least one vote record.' };
  }

  const headers = lines[0].split(',').map(h => h.trim().toLowerCase());
  const expected = ['fingerprint', 'voter_id', 'candidate', 'ip_address', 'timestamp'];
  if (!expected.every((field, index) => headers[index] === field)) {
    return {
      rows: [],
      error: 'CSV header must be exactly: fingerprint,voter_id,candidate,ip_address,timestamp'
    };
  }

  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const columns = lines[i].split(',').map(c => c.trim());
    if (columns.length !== expected.length) {
      return { rows: [], error: `Line ${i + 1} is malformed. Each line needs 5 comma-separated values.` };
    }

    const [fingerprint, voter_id, candidate, ip_address, timestamp] = columns;
    rows.push({ fingerprint, voter_id, candidate, ip_address, timestamp, rowNumber: i + 1 });
  }

  return { rows, error: null };
}

function analyzeVotes(votes) {
  const ipCount = new Map();
  const ipSameTime = new Map();
  const fingerprintCount = new Map();
  const fingerprintVoterMap = new Map();
  const missingRows = [];

  votes.forEach(vote => {
    const fingerprintKey = vote.fingerprint;
    const voterKey = vote.voter_id;
    const ipKey = vote.ip_address;
    const ipTimestampKey = `${ipKey}|${vote.timestamp}`;

    fingerprintCount.set(fingerprintKey, (fingerprintCount.get(fingerprintKey) ?? 0) + 1);

    const voters = fingerprintVoterMap.get(fingerprintKey) ?? new Set();
    voters.add(voterKey);
    fingerprintVoterMap.set(fingerprintKey, voters);

    ipCount.set(ipKey, (ipCount.get(ipKey) ?? 0) + 1);
    ipSameTime.set(ipTimestampKey, (ipSameTime.get(ipTimestampKey) ?? 0) + 1);

    if (!vote.fingerprint || !vote.voter_id || !vote.candidate || !vote.ip_address || !vote.timestamp) {
      missingRows.push(vote.rowNumber);
    }
  });

  const duplicateFingerprints = [...fingerprintCount.entries()]
    .filter(([, count]) => count > 1)
    .map(([fingerprint, count]) => ({ fingerprint, count }));

  const fingerprintMixedIds = [...fingerprintVoterMap.entries()]
    .filter(([, voters]) => voters.size > 1)
    .map(([fingerprint, voters]) => ({ fingerprint, voterIds: [...voters] }));

  const suspiciousIps = [...ipCount.entries()]
    .filter(([, count]) => count > 2)
    .map(([ip_address, count]) => ({ ip_address, count }));

  const timestampConflicts = [...ipSameTime.entries()]
    .filter(([, count]) => count > 1)
    .map(([key, count]) => {
      const [ip_address, timestamp] = key.split('|');
      return { ip_address, timestamp, count };
    });

  const anomalyDescriptions = [];
  if (duplicateFingerprints.length) {
    duplicateFingerprints.forEach(entry => {
      anomalyDescriptions.push({
        type: 'duplicate_fingerprint',
        title: 'Duplicate Fingerprint',
        description: `Fingerprint ${entry.fingerprint} appears ${entry.count} times. This indicates the same device or browser is voting repeatedly.`,
        badge: `${entry.count} votes`
      });
    });
  }

  if (fingerprintMixedIds.length) {
    fingerprintMixedIds.forEach(entry => {
      anomalyDescriptions.push({
        type: 'mixed_voter_ids',
        title: 'Fingerprint Used with Multiple Voter IDs',
        description: `Fingerprint ${entry.fingerprint} is associated with voter IDs ${entry.voterIds.join(', ')}. This suggests voter IDs may be faked.`,
        badge: `${entry.voterIds.length} IDs`
      });
    });
  }

  if (suspiciousIps.length) {
    suspiciousIps.forEach(entry => {
      anomalyDescriptions.push({
        type: 'multiple_ip',
        title: 'High Activity IP Address',
        description: `IP ${entry.ip_address} cast ${entry.count} votes. High vote volume from one IP is suspicious.`,
        badge: `${entry.count} votes`
      });
    });
  }

  if (timestampConflicts.length) {
    timestampConflicts.forEach(entry => {
      anomalyDescriptions.push({
        type: 'same_timestamp',
        title: 'Same Timestamp from Same IP',
        description: `IP ${entry.ip_address} recorded ${entry.count} votes at ${entry.timestamp}. This often means automated or fake voting.`,
        badge: `${entry.count} same-time votes`
      });
    });
  }

  if (missingRows.length) {
    anomalyDescriptions.push({
      type: 'missing_fields',
      title: 'Missing Required Fields',
      description: `Rows ${missingRows.join(', ')} are missing one or more required fields.`,
      badge: `${missingRows.length} rows`
    });
  }

  return {
    totalVotes: votes.length,
    duplicateFingerprints,
    fingerprintMixedIds,
    suspiciousIps,
    timestampConflicts,
    anomalies: anomalyDescriptions,
  };
}

function renderResults(analysis) {
  if (!analysis.anomalies.length) {
    resultsElement.innerHTML = `
      <div class="result-item">
        <strong>No suspicious patterns detected.</strong>
        <p class="meta">Total votes analyzed: ${analysis.totalVotes}</p>
        <span class="badge badge-success">Clean</span>
      </div>
    `;
    return;
  }

  const html = [
    `<div class="result-item">
        <strong>Suspicious voting activity found</strong>
        <p class="meta">Total votes analyzed: ${analysis.totalVotes}</p>
      </div>`,
    ...analysis.anomalies.map(anomaly => `
      <div class="result-item">
        <strong>${anomaly.title}</strong>
        <p>${anomaly.description}</p>
        <span class="badge badge-danger">${anomaly.badge}</span>
      </div>
    `)
  ];

  resultsElement.innerHTML = html.join('');
}

function showMessage(message, success = true) {
  resultsElement.innerHTML = `
    <div class="result-item">
      <strong>${success ? 'Success' : 'Error'}</strong>
      <p>${escapeHtml(message)}</p>
    </div>
  `;
}

function escapeHtml(text) {
  return text.replace(/[&<>"']/g, char => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[char]);
}
