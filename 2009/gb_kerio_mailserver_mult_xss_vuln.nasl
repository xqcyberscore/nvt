###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kerio_mailserver_mult_xss_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Kerio Mail Server Multiple Cross Site Scripting vulnerabilities
#
# Authors:
# Chandan S <schandan@secpod.com>
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

tag_impact = "Successful exploitation could result in insertion of arbitrary HTML and
  script code in a user's browser session in the context of an affected site.
  Impact Level: Application";
tag_affected = "Kerio MailServer before 6.6.2 on all running platform.";
tag_insight = "Issues are due to,
  - a folder and daytime parameters in mailCompose.php and calendarEdit.php
    files is not properly sanitised before being returned to the user.
  - input passed to the sent parameter in error413.php is not properly
    sanitised before being returned to the user.";
tag_solution = "Upgrade to Kerio MailServer 6.6.2
  http://www.kerio.com/kms_download.html";
tag_summary = "The host is running Kerio Mail Server and is prone to multiple
  cross site scripting vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800099");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-01-08 07:43:30 +0100 (Thu, 08 Jan 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-5760", "CVE-2008-5769");
  script_bugtraq_id(32863);
  script_name("Kerio Mail Server Multiple Cross Site Scripting vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32955");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/47398");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_kerio_mailserver_detect.nasl");
  script_require_keys("KerioMailServer/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

kerioVer = get_kb_item("KerioMailServer/Ver");
if(!kerioVer){
  exit(0);
}

if(version_is_less(version:kerioVer, test_version:"6.6.2")){
  security_message(0);
}
