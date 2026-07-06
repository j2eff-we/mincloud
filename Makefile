COMPOSE ?= docker compose
EXEC     = $(COMPOSE) exec -T mincloud /usr/local/bin/mincloud

.PHONY: help up down reset logs ps create-account whoami test

help: ## 사용 가능한 타깃 목록
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

up: ## 스택 빌드 후 기동 (dynamodb + mincloud)
	$(COMPOSE) up -d --build

down: ## 스택 내림 (계정 데이터=볼륨은 유지)
	$(COMPOSE) down

reset: ## 스택 + 볼륨까지 삭제 (계정 데이터 완전 초기화)
	$(COMPOSE) down -v

logs: ## mincloud 로그 팔로우
	$(COMPOSE) logs -f mincloud

ps: ## 컨테이너 상태
	$(COMPOSE) ps

create-account: ## 새 계정 + 루트 액세스키/시크릿 발급
	@$(EXEC) admin create-account

whoami: ## 키에서 계정 오프라인 복원 — make whoami KEY=AKIA...
	@$(EXEC) admin whoami $(KEY)

test: ## go 유닛 테스트
	go test ./...
