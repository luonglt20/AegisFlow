up:
	docker-compose up --build

down:
	docker-compose down

pipeline:
	docker-compose run pipeline-simulator

dashboard:
	open http://localhost:58080

clean:
	docker-compose down -v
