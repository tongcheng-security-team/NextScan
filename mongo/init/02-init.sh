mongoimport  -d $MONGO_DATABASE -u $MONGO_USERNAME -p $MONGO_PASSWORD -c  Engine_Config --type=json --file=/docker-entrypoint-initdb.d/Engine_Config.json
mongoimport  -d $MONGO_DATABASE -u $MONGO_USERNAME -p $MONGO_PASSWORD -c  Message_Template  --type=json --file=/docker-entrypoint-initdb.d/Message_Template.json
mongoimport  -d $MONGO_DATABASE -u $MONGO_USERNAME -p $MONGO_PASSWORD -c  System_Menu  --type=json --file=/docker-entrypoint-initdb.d/System_Menu.json
mongoimport  -d $MONGO_DATABASE -u $MONGO_USERNAME -p $MONGO_PASSWORD -c  System_Role  --type=json --file=/docker-entrypoint-initdb.d/System_Role.json
mongoimport  -d $MONGO_DATABASE -u $MONGO_USERNAME -p $MONGO_PASSWORD -c  System_RoleMenu  --type=json --file=/docker-entrypoint-initdb.d/System_RoleMenu.json
mongoimport  -d $MONGO_DATABASE -u $MONGO_USERNAME -p $MONGO_PASSWORD -c  System_User  --type=json --file=/docker-entrypoint-initdb.d/System_User.json
mongoimport  -d $MONGO_DATABASE -u $MONGO_USERNAME -p $MONGO_PASSWORD -c  System_UserRole  --type=json --file=/docker-entrypoint-initdb.d/System_UserRole.json
mongoimport  -d $MONGO_DATABASE -u $MONGO_USERNAME -p $MONGO_PASSWORD -c  Engine_Category  --type=json --file=/docker-entrypoint-initdb.d/Engine_Category.json
