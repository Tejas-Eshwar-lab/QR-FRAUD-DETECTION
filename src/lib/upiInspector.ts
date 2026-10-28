import { UpiPayload, HeuristicIndicator } from '../types/security';

export function inspectUpiPayment(upiData: UpiPayload): {
  indicators: HeuristicIndicator[];
  isSuspicious: boolean;
  warnings: string[];
  safeAdvice: string[];
} {
  const indicators: HeuristicIndicator[] = [];
  const warnings: string[] = [];
  const safeAdvice: string[] = [
    'Always verify the payee name in your trusted bank/UPI app before entering any PIN.',
    'IMPORTANT: You NEVER need to enter your UPI PIN to RECEIVE money, cashback, or lottery prizes.',
    'If someone claims scanning this QR code will deposit money into your bank account, it is a SCAM.',
  ];

  // 1. Check for suspicious cashback/lottery lures
  if (upiData.hasSuspiciousLure) {
    indicators.push({
      id: 'UPI_CASHBACK_LURE',
      category: 'Financial Fraud',
      severity: 'HIGH',
      title: 'Deceptive Reward / Cashback Lure Detected',
      description:
        'The QR note or merchant title contains words like "cashback", "reward", "lottery", or "refund". Scammers use these to trick victims into paying money thinking they are claiming a prize.',
      evidence: `Payee Note / Name: "${upiData.transactionNote || upiData.payeeName || ''}"`,
    });
    warnings.push('High-risk lure: The payment note promises cashback or rewards. Scanning cannot credit your account.');
  }

  // 2. Check for missing Payee Name (Pn)
  if (!upiData.payeeName) {
    indicators.push({
      id: 'UPI_MISSING_PAYEE_NAME',
      category: 'Payment Metadata',
      severity: 'LOW',
      title: 'No Registered Payee Name Specified',
      description: 'The QR code omits the `pn` (Payee Name) parameter. The recipient is solely identified by raw address.',
      evidence: `VPA: ${upiData.payeeAddress || 'None'}`,
    });
  }

  // 3. Check for unusually large or pre-set amount
  if (upiData.amount) {
    const numAmount = parseFloat(upiData.amount);
    if (!isNaN(numAmount) && numAmount > 10000) {
      indicators.push({
        id: 'UPI_HIGH_AMOUNT',
        category: 'Financial Exposure',
        severity: 'MEDIUM',
        title: `High Pre-filled Transfer Amount (₹${upiData.amount})`,
        description: `This QR code attempts to pre-fill a substantial debit of ₹${upiData.amount}. Verify the authorized order total.`,
        evidence: `Amount: ₹${upiData.amount} ${upiData.currency || 'INR'}`,
      });
    }
  } else {
    warnings.push('No amount is encoded: You will need to enter an amount manually if paying.');
  }

  // 4. Payee Address format check
  if (!upiData.isCleanPayeeFormat) {
    indicators.push({
      id: 'UPI_UNCONVENTIONAL_VPA',
      category: 'Payment Format',
      severity: 'MEDIUM',
      title: 'Unconventional or Malformed UPI ID',
      description: 'The payee address does not adhere to standard VPA format (e.g. username@bank).',
      evidence: `VPA: ${upiData.payeeAddress || 'Empty'}`,
    });
  }

  const isSuspicious = indicators.some((i) => i.severity === 'CRITICAL' || i.severity === 'HIGH');

  return {
    indicators,
    isSuspicious,
    warnings,
    safeAdvice,
  };
}
