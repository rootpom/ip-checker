# Contributing 

Thank you for your interest in contributing ! We welcome contributions from the community and appreciate your help in making this project better.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone. Please be kind, professional, and constructive in all interactions.

## How Can I Contribute?

### Reporting Bugs

If you find a bug, please create an issue with the following information:

- **Clear title**: Use a descriptive title for the issue
- **Description**: Explain what you expected to happen and what actually happened
- **Steps to reproduce**: Provide detailed steps to reproduce the bug
- **Environment details**: Include Python version, OS, and any relevant system information
- **Screenshots**: If applicable, add screenshots to help explain the problem

**Template:**
```
**Bug Description:**
A clear description of what the bug is.

**To Reproduce:**
1. Run the scanner with '...'
2. Enter target '...'
3. See error

**Expected Behavior:**
What you expected to happen.

**Environment:**
- OS: [e.g., Ubuntu 22.04]
- Python Version: [e.g., 3.10.5]

**Additional Context:**
Any other information about the problem.
```

### Suggesting Enhancements

We love new ideas! To suggest an enhancement:

- **Check existing issues**: Make sure your idea hasn't been suggested already
- **Explain the benefit**: Describe why this enhancement would be useful
- **Provide examples**: Show how the feature would work
- **Consider alternatives**: Mention any alternative solutions you've considered

### Pull Requests

#### Before Submitting

1. **Check existing PRs**: Make sure someone hasn't already worked on this
2. **Create an issue first**: For major changes, discuss them in an issue before starting
3. **Follow the code style**: Match the existing code formatting and style
4. **Test your changes**: Make sure everything works as expected

#### Pull Request Process

1. **Fork the repository** and create your branch from `main`:
```bash
git checkout -b feature/your-feature-name
```

2. **Make your changes**:
   - Write clear, concise code
   - Add comments for complex logic
   - Follow Python best practices (PEP 8)

3. **Test thoroughly**:
   - Test on different targets (localhost, valid hosts)
   - Test error handling
   - Test edge cases

4. **Commit your changes**:
```bash
git add .
git commit -m "Add: brief description of your changes"
```

Use conventional commit messages:
- `Add:` for new features
- `Fix:` for bug fixes
- `Update:` for updates to existing features
- `Docs:` for documentation changes
- `Refactor:` for code refactoring

5. **Push to your fork**:
```bash
git push origin feature/your-feature-name
```

6. **Open a Pull Request**:
   - Provide a clear title and description
   - Reference any related issues
   - Explain what changes you made and why
   - Include screenshots for UI changes (if applicable)

#### Pull Request Template

```
**Description:**
Brief description of changes.

**Related Issue:**
Fixes #(issue number)

**Type of Change:**
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

**Testing:**
Describe how you tested your changes.

**Checklist:**
- [ ] My code follows the project's style guidelines
- [ ] I have tested my changes
- [ ] I have commented my code where necessary
- [ ] I have updated the documentation if needed
```

## Development Guidelines

### Code Style

- Follow PEP 8 style guidelines
- Use meaningful variable and function names
- Keep functions small and focused (single responsibility)
- Add docstrings to functions and classes
- Use type hints where appropriate


### Adding New Features

When adding features:
- Keep it simple and maintainable
- Don't add unnecessary dependencies
- Make features optional when possible
- Update the README with usage examples
- Add error handling

### Testing

Before submitting:
- Test on multiple Python versions (3.6+)
- Test on different operating systems if possible
- Test both valid and invalid inputs
- Test error conditions

### Documentation

- Update README.md if you add new features
- Add inline comments for complex code
- Update usage examples
- Keep documentation clear and concise

## Project Structure

```
ip-checker/
├── iplookup.py      # Main ip lookup script
├── README.md            # Project documentation
├── CONTRIBUTING.md      # This file
├── LICENSE              # License information
└── .gitignore          # Git ignore rules
```

## Getting Help

If you need help:
- Check existing issues and discussions
- Read the README carefully
- Ask questions in a new issue with the "question" label


## Recognition

All contributors will be acknowledged in the project. Thank you for helping make this project better!

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (MIT License).

---

Thank you for contributing ! 🎉
