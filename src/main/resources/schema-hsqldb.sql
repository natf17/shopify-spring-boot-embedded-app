/*                         StoreAccessTokens
 * -----------------------------------------------------------------------------------------------------------------|
 * |  id  |  		shop  		  |  		     access_token  			 	 |  			  scope                 | 
 * |----------------------------------------------------------------------------------------------------------------|
 * | 4324 |  "lmdev.myshopify.com"  |   "tuyiujhvbgvhgvjyj7676tig76gi6gi7"   |    "read_inventory,write_inventory"  |
 * |________________________________________________________________________________________________________________|
 * 
 */




CREATE TABLE STOREACCESSTOKENS(
					id 		  			BIGINT 		  	NOT NULL		IDENTITY, 
					shop 			    VARCHAR(50)   	NOT NULL,
					access_token        VARCHAR(50)   	NOT NULL,
					scope 			    VARCHAR(200)    NOT NULL,					
					
					);