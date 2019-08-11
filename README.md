# webauthn-POC
Proof-Of-Concept implementation of webauthn (works solo keys)


### Database
You need to have a mysql/mariadb running with the following table, in database "fido2"
```
--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `users` (
  `userid` int(11) NOT NULL AUTO_INCREMENT,
  `publickey` text NOT NULL,
  `username` text NOT NULL,
  `credentialid` text NOT NULL,
  PRIMARY KEY (`userid`)
) ENGINE=InnoDB AUTO_INCREMENT=17 DEFAULT CHARSET=utf8mb4;
```
