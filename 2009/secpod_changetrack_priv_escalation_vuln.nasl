###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_changetrack_priv_escalation_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Changetrack Local Privilege Escalation Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Attacker may leverage this issue by executing arbitrary commands via CRLF
  sequences and shell metacharacters in a filename in a directory that is
  checked by changetrack.
  Impact Level: Application";
tag_affected = "Changetrack version 4.3";
tag_insight = "This flaw is generated because the application does not properly handle
  certain file names.";
tag_solution = "Upgrade to Changetrack version 4.7 or later
  For updates refer to http://changetrack.sourceforge.net/";
tag_summary = "This host has Changetrack installed and is prone to Local Privilege
  Escalation vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900868");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-09-24 10:05:51 +0200 (Thu, 24 Sep 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3233");
  script_bugtraq_id(36420);
  script_name("Changetrack Local Privilege Escalation Vulnerability");
  script_xref(name : "URL" , value : "http://bugs.debian.org/546791");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36756");
  script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=546791");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2009/09/16/3");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Privilege escalation");
  script_dependencies("secpod_changetrack_detect.nasl");
  script_require_keys("Changetrack/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

ctrack_ver = get_kb_item("Changetrack/Ver");
if(!ctrack_ver){
  exit(0);
}

# Check for Changetrack version 4.3
if(version_is_equal(version:ctrack_ver, test_version:"4.3")){
  security_message(0);
}
