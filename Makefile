
.PHONY: help
help:
	@echo "Usage: make <target>"
	@echo
	@echo "Targets:"
	@echo "  help               -- show this help"
	@echo "  enable-git-hooks   -- enable git hooks in this local repo clone"
	@echo "  disable-git-hooks  -- enable git hooks in this local repo clone"

.PHONY: enable-git-hooks
enable-git-hooks:
	git config core.hooksPath .githooks

.PHONY: disable-git-hooks
disable-git-hooks:
	git config --unset core.hooksPath

