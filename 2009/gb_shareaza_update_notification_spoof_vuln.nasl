###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_shareaza_update_notification_spoof_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Shareaza Update Notification Spoofing Vulnerability
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

tag_impact = "Successful exploitation will let the attackers conduct spoofing attacks.
  Impact Level: Application";
tag_affected = "Shareaza version prior to 2.3.1.0";
tag_insight = "The flaw is due to update notifications being handled via the domain
  update.shareaza.com, which is no longer controlled by the vendor. This can
  be exploited to spoof update notifications.";
tag_solution = "Upgrade Shareaza version to 2.3.1.0
  http://shareaza.sourceforge.net/?id=download";
tag_summary = "This host has Shareaza installed and is prone Update Notification
  Spoofing vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800604");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-09-11 18:01:06 +0200 (Fri, 11 Sep 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-7164");
  script_bugtraq_id(27171);
  script_name("Shareaza Update Notification Spoofing Vulnerability");


  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_shareaza_detect.nasl");
  script_require_ports("Services/www", 6346);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://secunia.com/advisories/28302");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/39484");
  script_xref(name : "URL" , value : "http://sourceforge.net/project/shownotes.php?group_id=110672&release_id=565250");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

shareazaPort = get_http_port(default:6346);

if(!shareazaPort){
  exit(0);
}

shareazaVer = get_kb_item("www/" + shareazaPort + "/Shareaza");

if(shareazaVer != NULL)
{
  # Check for Shareaza versions prior to 2.3.1.0
  if(version_is_less(version:shareazaVer, test_version:"2.3.1.0")){
    security_message(shareazaPort);
  }
}
