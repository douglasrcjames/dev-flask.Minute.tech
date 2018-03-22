-- MySQL dump 10.13  Distrib 5.7.21, for Linux (x86_64)
--
-- Host: localhost    Database: minutetech
-- ------------------------------------------------------
-- Server version	5.7.21-0ubuntu0.17.10.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `clients`
--

DROP TABLE IF EXISTS `clients`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `clients` (
  `cid` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `phone` varchar(255) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `password` varchar(255) DEFAULT NULL,
  `rating` int(4) DEFAULT '500',
  PRIMARY KEY (`cid`),
  UNIQUE KEY `phone` (`phone`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `clients`
--

LOCK TABLES `clients` WRITE;
/*!40000 ALTER TABLE `clients` DISABLE KEYS */;
INSERT INTO `clients` VALUES (1,'9168025609','douglasrcjames@gmail.com','$5$rounds=535000$XiTzCg0XqLuEYrAI$lucvtuC/p4/LEO4etjSsKN7ZjB3UUCrrpucXdLK0WH2',500),(2,'9168125609','doug@minute.tech','$5$rounds=535000$lSsy6n0nGyF3m06V$VVBgtDhDA9aDrOmHHzorngJg758X22/9bgCb1vmDFY1',500),(3,'8314029881','aurorachun6195@gmail.com','$5$rounds=535000$CYgjJEO.kIGd.M/X$8x/YdqCxddtwGV1mG3EHXWLHFXOJoUk1ve.TyXMP.3A',500),(4,'9168525609','douglasrcjames123@gmail.com','$5$rounds=535000$siXFX4qDE2SwM0fk$OM5FEvt.DeyYAjUKiCusZ9wxyPsHx9HI19C3JGN7Zr.',500);
/*!40000 ALTER TABLE `clients` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `contact`
--

DROP TABLE IF EXISTS `contact`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `contact` (
  `contact_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `uid` bigint(20) unsigned DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `message` text,
  PRIMARY KEY (`contact_id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `contact`
--

LOCK TABLES `contact` WRITE;
/*!40000 ALTER TABLE `contact` DISABLE KEYS */;
INSERT INTO `contact` VALUES (1,0,'previn.wong@gmail.com','what\'s up bro.'),(2,0,'lorain@gmail.com','Are you really open for everything?');
/*!40000 ALTER TABLE `contact` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `cpersonals`
--

DROP TABLE IF EXISTS `cpersonals`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `cpersonals` (
  `cid` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `first_name` varchar(255) DEFAULT NULL,
  `last_name` varchar(255) DEFAULT NULL,
  `address` varchar(255) DEFAULT 'Not Provided',
  `city` varchar(255) DEFAULT 'Not Provided',
  `state` varchar(100) DEFAULT 'NA',
  `zip` varchar(16) DEFAULT NULL,
  `birth_year` int(5) DEFAULT '1899',
  `birth_month` varchar(10) DEFAULT 'January',
  `birth_day` int(3) DEFAULT '1',
  `bio` text,
  `lang_pref` varchar(64) DEFAULT 'Not Provided',
  `time_zone` varchar(64) DEFAULT 'Not Provided',
  `launch_email` int(1) DEFAULT '0',
  `prof_pic` longblob,
  `reg_date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`cid`),
  CONSTRAINT `cpersonals_ibfk_1` FOREIGN KEY (`cid`) REFERENCES `clients` (`cid`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `cpersonals`
--

LOCK TABLES `cpersonals` WRITE;
/*!40000 ALTER TABLE `cpersonals` DISABLE KEYS */;
INSERT INTO `cpersonals` VALUES (1,'Douglas','James','Not provided','San Jose','California','95110',1899,'January',1,'Not provided','Not Provided','Not Provided',0,'/static/user_info/prof_pic/default.jpg','2018-02-27 02:53:20'),(2,'Douglas','James','Not provided','Not provided','NA','95110',1899,'January',1,'Not provided','Not Provided','Not Provided',0,'/static/user_info/prof_pic/default.jpg','2018-02-27 09:15:08'),(3,'Aurora ','Chun ','Not provided','Not provided','NA','95112',1899,'January',1,'Not provided','Not Provided','Not Provided',0,'/static/user_info/prof_pic/default.jpg','2018-02-28 05:42:27'),(4,'Douglas','James','Not provided','Not provided','NA','95110',1899,'January',1,'Not provided','Not Provided','Not Provided',1,'/static/user_info/prof_pic/default.jpg','2018-03-07 23:45:00');
/*!40000 ALTER TABLE `cpersonals` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `technicians`
--

DROP TABLE IF EXISTS `technicians`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `technicians` (
  `tid` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `phone` varchar(255) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `password` varchar(255) DEFAULT NULL,
  `rating` int(4) DEFAULT '500',
  PRIMARY KEY (`tid`),
  UNIQUE KEY `phone` (`phone`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `technicians`
--

LOCK TABLES `technicians` WRITE;
/*!40000 ALTER TABLE `technicians` DISABLE KEYS */;
INSERT INTO `technicians` VALUES (1,'9495736821','aradmomen@yahoo.com','$5$rounds=535000$hRJuY8M7Kmt2he9r$i3v7u8JV/F7IHyy/jtGHL/1Dk5tK/A5sLp5A1A8BVg6',500),(2,'9168025609','douglasrcjames@gmail.com','$5$rounds=535000$tdDbmqkHnOMz7y4n$1Z5Fql3FV/auA/5SmzMX8JIjk8lK.bJGhAygEKaGYe1',500),(3,'9168225609','admin@minute.tech','$5$rounds=535000$S3SZSjS6bqLnW4gG$PZkjrAqqjZkzIqA5SyF/gMNFvyA7VMOwl1rcVuKXS3.',500);
/*!40000 ALTER TABLE `technicians` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `threads`
--

DROP TABLE IF EXISTS `threads`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `threads` (
  `thrid` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `qid` bigint(20) unsigned DEFAULT NULL,
  `cid` bigint(20) unsigned DEFAULT NULL,
  `tid` bigint(20) unsigned DEFAULT NULL,
  `body` text,
  `img` longblob,
  `caption` varchar(255) DEFAULT NULL,
  `answered` int(1) DEFAULT '0',
  PRIMARY KEY (`thrid`),
  KEY `qid` (`qid`),
  KEY `tid` (`tid`),
  KEY `cid` (`cid`),
  CONSTRAINT `threads_ibfk_1` FOREIGN KEY (`qid`) REFERENCES `tickets` (`qid`),
  CONSTRAINT `threads_ibfk_2` FOREIGN KEY (`tid`) REFERENCES `technicians` (`tid`),
  CONSTRAINT `threads_ibfk_3` FOREIGN KEY (`cid`) REFERENCES `clients` (`cid`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `threads`
--

LOCK TABLES `threads` WRITE;
/*!40000 ALTER TABLE `threads` DISABLE KEYS */;
/*!40000 ALTER TABLE `threads` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tickets`
--

DROP TABLE IF EXISTS `tickets`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tickets` (
  `qid` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `cid` bigint(20) unsigned DEFAULT NULL,
  `tid` bigint(20) unsigned DEFAULT NULL,
  `difficulty` int(2) DEFAULT '0',
  `priority` int(4) DEFAULT '500',
  `time_stamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `solved` int(1) DEFAULT '0',
  `pending` int(1) DEFAULT '0',
  `archived` int(1) DEFAULT '0',
  `title` varchar(60) DEFAULT NULL,
  `tags` text,
  `answer` text,
  PRIMARY KEY (`qid`),
  KEY `tid` (`tid`),
  KEY `cid` (`cid`),
  CONSTRAINT `tickets_ibfk_1` FOREIGN KEY (`tid`) REFERENCES `technicians` (`tid`),
  CONSTRAINT `tickets_ibfk_2` FOREIGN KEY (`cid`) REFERENCES `clients` (`cid`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tickets`
--

LOCK TABLES `tickets` WRITE;
/*!40000 ALTER TABLE `tickets` DISABLE KEYS */;
/*!40000 ALTER TABLE `tickets` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tpersonals`
--

DROP TABLE IF EXISTS `tpersonals`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tpersonals` (
  `tid` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `first_name` varchar(255) DEFAULT NULL,
  `last_name` varchar(255) DEFAULT NULL,
  `address` varchar(255) DEFAULT NULL,
  `city` varchar(255) DEFAULT NULL,
  `state` varchar(100) DEFAULT NULL,
  `zip` varchar(16) DEFAULT NULL,
  `birth_year` int(5) DEFAULT '1800',
  `birth_month` varchar(10) DEFAULT 'January',
  `birth_day` int(3) DEFAULT '1',
  `linked_in` varchar(255) DEFAULT NULL,
  `bio` text,
  `lang_pref` varchar(64) DEFAULT 'Not Provided',
  `time_zone` varchar(64) DEFAULT 'Not Provided',
  `launch_email` int(1) DEFAULT '0',
  `prof_pic` longblob,
  `tags` text,
  `signature` varchar(255) DEFAULT NULL,
  `reg_date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`tid`),
  CONSTRAINT `tpersonals_ibfk_1` FOREIGN KEY (`tid`) REFERENCES `technicians` (`tid`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tpersonals`
--

LOCK TABLES `tpersonals` WRITE;
/*!40000 ALTER TABLE `tpersonals` DISABLE KEYS */;
INSERT INTO `tpersonals` VALUES (1,'Arad','Momen','22806 Via Santa Rosa','Mission Viejo','CA','92691',1800,'January',9,NULL,'Not provided','Not Provided','Not Provided',1,'/static/tech_user_info/prof_pic/default.jpg',NULL,'Arad Momen','2018-02-27 02:24:08'),(2,'Douglas','James','814 Vine Street','San Jose','CA','95110',1800,'January',1,NULL,'Not provided','Not Provided','Not Provided',1,'/static/tech_user_info/prof_pic/default.jpg',NULL,NULL,'2018-02-28 03:19:32'),(3,'Douglas','James','814 Vine Street','San Jose','CA','95110',1800,'January',1,NULL,'Not provided','Not Provided','Not Provided',0,'/static/tech_user_info/prof_pic/default.jpg',NULL,NULL,'2018-03-07 23:45:53');
/*!40000 ALTER TABLE `tpersonals` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2018-03-22 10:56:52
