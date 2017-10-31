###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_symantec_im_manager_code_inj_vuln.nasl 7573 2017-10-26 09:18:50Z cfischer $
#
# Symantec IM Manager 'eval()' Code Injection Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attacker to execute arbitrary code on
  the system.
  Impact Level: Application";
tag_affected = "Symantec IM Manager versions 8.4.16 and prior";
tag_insight = "The flaw is caused by an input validation error in the 'ScheduleTask' method
  of the 'IMAdminSchedTask.asp' page within the administration console when
  processing a POST variable via an 'eval()' call, which could be exploited by
  attackers to inject and execute arbitrary ASP code by enticing a logged-in
  console user to visit a malicious link.";
tag_solution = "Upgarade to Symantec IM Manager version 8.4.17 or later.
  For updates refer to http://www.symantec.com/business/im-manager";
tag_summary = "This host is installed with Symantec IM Manager and is prone to
  code injection vulnerability.";

if(description)
{
  script_id(901186);
  script_version("$Revision: 7573 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 11:18:50 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2011-02-28 11:12:07 +0100 (Mon, 28 Feb 2011)");
  script_cve_id("CVE-2010-3719");
  script_bugtraq_id(45946);
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_name("Symantec IM Manager 'eval()' Code Injection Vulnerability");


  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_require_keys("Symantec/IM/Manager");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/65040");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0259");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-037");
  script_xref(name : "URL" , value : "http://www.symantec.com/business/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2011&suid=20110131_00");
  exit(0);
}


include("version_func.inc");

## Get Version from KB
imVer = get_kb_item("Symantec/IM/Manager");
if(!imVer){
  exit(0);
}

if(version_is_less_equal(version:imVer, test_version:"8.4.16")) {
  security_message(port:0);
}
