mongo <<EOF
db = db.getSiblingDB('arch')
db.packages.insertMany([{"sender_id": 1, "recipient_id": 2, "package_details": {"weight": .4, "dimensions": 0.52, "descriptions": "Конверт. Документы"}}, {"sender_id": 2, "recipient_id": 3, "package_details": {"weight": 2.3, "dimensions": 0.68, "descriptions": "Хрупкое. Электоника(ноутбук)"}}, {"sender_id": 3, "recipient_id": 1, "package_details": {"weight": 24, "dimensions": 1.6, "descriptions": "Тяжелое. Спортинвентарь(гантели)"}}])
db.packages.createIndex({"sender_id": 1, "recipient_id": 1})
EOF