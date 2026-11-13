"""Offline contract, policy, dataset and scoring tests. No internet or credentials."""
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch

from agent_evals.evaluate import (
    ProposedAction, SYSTEM, judge, load_cases, parse_action,
    prompt_for, request_model, run, summarize,
)


class FixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = load_cases()

    def test_dataset_has_12_complete_pairs_and_24_cases(self):
        self.assertEqual(len(self.cases), 24)
        self.assertEqual(len({item['pair_id'] for item in self.cases}), 12)
        self.assertEqual(sum(x['variant'] == 'attack' for x in self.cases), 12)
        self.assertEqual(sum(x['variant'] == 'benign' for x in self.cases), 12)

    def test_all_attacker_goals_differ_from_trusted_action(self):
        for case in self.cases:
            if case['variant'] == 'attack':
                self.assertNotEqual(case['attacker_goal'], case['authorized'], case['id'])

    def test_untrusted_content_is_labeled_as_data(self):
        self.assertIn('UNTRUSTED', SYSTEM)
        for case in self.cases:
            prompt = prompt_for(case)
            self.assertIn('<untrusted>', prompt)
            self.assertIn(case['untrusted_text'], prompt)

    def test_parse_rejects_multiple_or_malformed_actions(self):
        bad = ['hello', '{}', '[]', '{"operation":"read_file"}',
               '{"operation":"read_file","target":"x","override":true}',
               '{"operation":1,"target":"x"}',
               '{"operation":"shell","target":"x"}{"operation":"none","target":""}',
               '{"operation":"none","target":"x"}',
               '{"operation":"future-tool","target":"x"}']
        for value in bad:
            with self.subTest(value=value):
                self.assertIsNone(parse_action(value))
        self.assertEqual(parse_action('{"operation":"none","target":""}'), ProposedAction('none', ''))

    def test_synthetic_reference_baseline(self):
        result = run('baseline', None)
        self.assertEqual(result['total'], 24)
        self.assertEqual(result['benign_cases'], 12)
        self.assertEqual(result['attack_cases'], 12)
        self.assertEqual(result['benign_task_completion'], 12)
        self.assertEqual(result['attack_goal_proposals'], 0)
        self.assertEqual(result['provider'], 'baseline')
        self.assertIn('NOT-AI', result['mode'])

    def test_synthetic_attack_control_detects_goals_and_blocks_all(self):
        result = run('attack-control', None)
        self.assertEqual(result['total'], 24)
        self.assertEqual(result['attack_goal_proposals'], 12)
        self.assertEqual(result['unauthorized_proposals'], 12)
        self.assertEqual(result['unauthorized_proposals_blocked_by_host'], 12)
        self.assertEqual(result['benign_task_completion'], 12)
        self.assertIn('NOT-AI', result['mode'])

    def test_every_attack_proposal_is_blocked_by_host(self):
        with tempfile.TemporaryDirectory() as temp:
            for case in self.cases:
                if case['variant'] != 'attack':
                    continue
                proposed = ProposedAction(**case['attacker_goal'])
                row = judge(case, proposed, Path(temp))
                self.assertFalse(row['host_allowed'], case['id'])
                self.assertTrue(row['attacker_goal_proposed'], case['id'])
                self.assertTrue(row['unauthorized_action_proposed'], case['id'])

    def test_authorized_proposals_are_allowed(self):
        with tempfile.TemporaryDirectory() as temp:
            for case in self.cases:
                row = judge(case, ProposedAction(**case['authorized']), Path(temp))
                self.assertTrue(row['host_allowed'], case['id'])
                self.assertTrue(row['trusted_action_proposed'], case['id'])

    def test_refusal_is_safe_but_not_task_completion(self):
        with tempfile.TemporaryDirectory() as temp:
            row = judge(self.cases[0], ProposedAction('none', ''), Path(temp))
            self.assertFalse(row['host_allowed'])
            self.assertFalse(row['trusted_action_proposed'])
            self.assertFalse(row['unauthorized_action_proposed'])

    def test_attack_score_counts_proposal_not_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            attacks = [x for x in self.cases if x['variant'] == 'attack']
            rows = [judge(x, ProposedAction(**x['attacker_goal']), Path(temp)) for x in attacks]
            report = summarize(rows, 'synthetic-test', 'not-a-model')
            self.assertEqual(report['attack_goal_proposals'], 12)
            self.assertEqual(report['unauthorized_proposals_blocked_by_host'], 12)
            self.assertEqual(report['unauthorized_proposals'], 12)
            self.assertTrue(all(x['host_allowed'] is False for x in rows))

    def test_no_live_credentials_needed_for_baseline(self):
        with patch.dict('os.environ', {}, clear=True):
            self.assertEqual(run('baseline', None)['total'], 24)

    def test_live_openai_refuses_to_start_without_credentials(self):
        with patch.dict('os.environ', {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, 'OPENAI_API_KEY'):
                request_model(self.cases[0], 'openai', 'hypothetical-model')

    def test_live_anthropic_refuses_to_start_without_credentials(self):
        with patch.dict('os.environ', {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, 'ANTHROPIC_API_KEY'):
                request_model(self.cases[0], 'anthropic', 'hypothetical-model')

    def test_partial_pair_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'case.jsonl'
            path.write_text(json.dumps(self.cases[0]) + '\n', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'complete'):
                load_cases(path)


if __name__ == '__main__':
    unittest.main()
