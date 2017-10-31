###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_memcached_info_disclosure_vuln.nasl 7573 2017-10-26 09:18:50Z cfischer $
#
# Memcached Information Disclosure Vulnerabilities
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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

tag_impact = "Successful exploitation will let the attacker craft malicious commands and
  pass it to the vulnerable functions to gain sensitive information about the
  application i.e. disclosure of locations of memory regions and defeat ASLR
  protections, by sending a command to the daemon's TCP port.";
tag_affected = "Memcached version prior to 1.2.8";
tag_insight = "- Error in process_stat function discloses the contents of /proc/self/maps in
    response to a stats maps command.
  - Error in process_stat function which discloses memory allocation statistics
    in response to a stats malloc command.";
tag_solution = "Upgrade to the latest version 1.2.8
  http://www.danga.com/memcached";
tag_summary = "The host is running Memcached and is prone to Information Disclosure
  Vulnerabilities.";

if(description)
{
  script_id(800715);
  script_version("$Revision: 7573 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 11:18:50 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-1255", "CVE-2009-1494");
  script_bugtraq_id(34756);
  script_name("Memcached Information Disclosure Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34915");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1196");
  script_xref(name : "URL" , value : "http://www.positronsecurity.com/advisories/2009-001.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_memcached_detect.nasl");
  script_require_keys("MemCached/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

memcachedVer = get_kb_item("MemCached/Ver");
if(memcachedVer == NULL){
  exit(0);
}

# Grep for Memcached version prior to 1.2.8
if(version_is_less(version:memcachedVer, test_version:"1.2.8")){
  security_message(port:0);
}
