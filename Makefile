up:
	docker-compose up --build

down:
	docker-compose down

pipeline:
	docker-compose run --rm aegisflow bash pipeline/run_pipeline.sh

dashboard:
	open http://localhost:58081

clean:
	docker-compose down -v
