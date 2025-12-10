# Security Notes

This document provides basic security considerations for your SubConv deployment.

## Default Configuration

By default, SubConv relies on:
- **Domain randomness** - Vercel assigns random subdomains
- **HTTPS encryption** - All traffic is encrypted

## Built-in Protection

- **Search engine blocking** is enabled by default
- Robots.txt will deny all search engine crawlers

## Security by Obscurity

For personal use:
- Your Vercel domain is randomly generated (e.g., `subconv-abc123.vercel.app`)
- Without knowing the exact URL, discovery is extremely unlikely
- The probability of guessing is approximately 1 in 62^20

## Best Practices

1. **Don't share your subscription URL** publicly
2. **Use HTTPS** - Vercel handles this automatically
3. **Monitor usage** in Vercel dashboard if concerned