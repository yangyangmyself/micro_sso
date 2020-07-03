DROP TABLE IF EXISTS `oauth_client_details`;
CREATE TABLE `oauth_client_details` (
  `client_id` varchar(256) NOT NULL COMMENT '客户端编号',
  `client_secret` varchar(256) NOT NULL COMMENT '客户端密码',
  `resource_ids` varchar(256) DEFAULT NULL,
  `scope` varchar(256) DEFAULT NULL,
  `authorized_grant_types` varchar(256) DEFAULT NULL,
  `web_server_redirect_uri` varchar(256) DEFAULT NULL,
  `authorities` varchar(256) DEFAULT NULL,
  `access_token_validity` int(11) DEFAULT NULL,
  `refresh_token_validity` int(11) DEFAULT NULL,
  `additional_information` varchar(4096) DEFAULT NULL,
  `autoapprove` varchar(256) DEFAULT NULL,
  PRIMARY KEY (`client_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COMMENT='第三方应用客户端登录信息表';

-- ----------------------------
-- Records of oauth_client_details
-- ----------------------------
INSERT INTO `oauth_client_details` VALUES ('qq', '123456', null, 'read,write', 'authorization_code,client_credentials,password,refresh_token,implicit', 'http://localhost:8066/token.html', 'ADMIN', '3600', '3600', null, 'true,false');

DROP TABLE IF EXISTS `t_ac_sysuser`;
CREATE TABLE `t_ac_sysuser` (
  `yhdh` varchar(30) NOT NULL ,
  `yhmc` varchar(30) NOT NULL,
  `mm` varchar(4000) NOT NULL ,
  `sfzmhm` varchar(18) DEFAULT 
  PRIMARY KEY (`yhdh`),
  KEY `index_yhdh` (`yhdh`) USING BTREE,
) ENGINE=MyISAM DEFAULT CHARSET=utf8 ;
INSERT INTO `t_ac_sysuser` (`yhdh`, `yhmc`, `mm`, `sfzmhm`);
