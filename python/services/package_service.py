from fastapi import HTTPException, status
from model.model import Package_description, Package, package_collection
from bson import ObjectId

# ==== Package service ================================================================================================

class package_service():

	async def create_package(self, package_desc: Package_description, current_user: dict):
		if package_desc.recipient_id == current_user["user"].id:
			raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You can't send a package to yourself")
		insert_obj = {"sender_id": current_user["user"].id, "recipient_id": package_desc.recipient_id, "package_details": {"package_weight": package_desc.package_details["weight"], "package_dimensions": package_desc.package_details["dimensions"], "package_descriptions": package_desc.package_details["descriptions"]}}
		package_collection.insert_one(insert_obj)
		insert_obj["_id"] = str(insert_obj["_id"])
		return insert_obj

	async def get_user_packages(self, current_user: dict):
		find_result = []
		for doc in package_collection.find({"$or": [{"sender_id": current_user["user"].id}, {"recipient_id": current_user["user"].id}]}):
			doc["_id"] = str(doc["_id"])
			find_result.append(doc)
		return find_result

	async def update_package(self, updated_package: dict, current_user: dict):
		package = package_collection.find_one({"_id": ObjectId(updated_package["_id"])})
		if package is None:
			raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Package not found")
		if (package["sender_id"] == current_user["user"].id) or (package["recipient_id"] == current_user["user"].id):
			package_collection.update_one({"_id": ObjectId(updated_package["_id"])}, {"$set": {"sender_id": updated_package["sender_id"], "recipient_id": updated_package["recipient_id"], "package_details": updated_package["package_details"]}})
			return updated_package
		else:
			raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You can only change package related to the current account")

	async def delete_package(self, product_id: str, current_user: dict):
		package = package_collection.find_one({"_id": ObjectId(product_id)})
		if package is None:
			raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Package not found")
		if (package["sender_id"] == current_user["user"].id) or (package["recipient_id"] == current_user["user"].id):
			package_collection.delete_one({"_id": ObjectId(package["_id"])})
			package["_id"] = str(package["_id"])
			return package
		else:
			raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You can only change package related to the current account")

# =====================================================================================================================