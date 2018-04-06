##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openoffice_code_exec_vuln_lin_900043.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: OpenOffice rtl_allocateMemory() Remote Code Execution Vulnerability
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

tag_impact = "Attackers can cause an out of bounds array access by tricking a
        user into opening a malicious document, also allow execution of arbitrary
        code.
 Impact Level : System";

tag_solution = "Upgrade to OpenOffice.org Version 3.2.0 or later,
 For updates refer to http://download.openoffice.org/index.html";

tag_affected = "OpenOffice.org 2.4.1 and prior on Linux.";

tag_insight = "The issue is due to a numeric truncation error within the rtl_allocateMemory()
        method in alloc_global.c file.";


tag_summary = "This host has OpenOffice.Org installed, which is prone to remote
 code execution vulnerability.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.900043");
 script_version("$Revision: 9349 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-09-02 07:39:00 +0200 (Tue, 02 Sep 2008)");
 script_bugtraq_id(30866);
 script_cve_id("CVE-2008-3282");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"package");
 script_family("General");
 script_name("OpenOffice rtl_allocateMemory() Remote Code Execution Vulnerability (Linux)");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/rpms", "login/SSH/success");
 script_exclude_keys("ssh/no_linux_shell");

 script_xref(name : "URL" , value : "http://secunia.com/advisories/31640/");
 script_xref(name : "URL" , value : "http://www.frsirt.com/english/advisories/2008/2449");
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "affected" , value : tag_affected);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "impact" , value : tag_impact);
 exit(0);
}

 foreach item (get_kb_list("ssh/login/rpms"))
 {
	if(egrep(pattern:"^(O|o)pen(O|o)ffice.*?~([01]\..*|2\.([0-3][^0-9]" +
			 "|4(\.[01])?[^.0-9]))", string:item))
	{
 		security_message(port:0);
      		exit(0);
        }
 }
