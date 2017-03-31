###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dovecot_base_dir_sec_bypass_vuln.nasl 4865 2016-12-28 16:16:43Z teissa $
#
# Description: Dovecot 'base_dir' Insecure Permissions Security Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful attack could allow malicious people to log in as another user,
  which may aid in further attacks.
  Impact Level: System";
tag_affected = "Dovecot versions 1.2 before 1.2.8";
tag_insight = "This flaw is due to insecure permissions (0777) being set on the 'base_dir'
  directory and its parents, which could allow malicious users to replace auth
  sockets and log in as other users.";
tag_solution = "Apply the patch or upgrade to Dovecot version 1.2.8
  http://www.dovecot.org/download.html";
tag_summary = "This host has Dovecot installed and is prone to Security Bypass
  Vulnerability";

if(description)
{
  script_id(801055);
  script_version("$Revision: 4865 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-28 17:16:43 +0100 (Wed, 28 Dec 2016) $");
  script_tag(name:"creation_date", value:"2009-12-02 13:54:57 +0100 (Wed, 02 Dec 2009)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3897");
  script_bugtraq_id(37084);
  script_name("Dovecot 'base_dir' Insecure Permissions Security Bypass Vulnerability");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/54363");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3306");
  script_xref(name : "URL" , value : "http://www.dovecot.org/list/dovecot-news/2009-November/000143.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_dovecot_detect.nasl");
  script_require_keys("Dovecot/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

dovecotVer = get_kb_item("Dovecot/Ver");
if((dovecotVer != NULL) && (dovecotVer =~ "^1\.2"))
{
  if(version_is_less(version:dovecotVer, test_version:"1.2.8")){
    security_message(0);
  }
}
