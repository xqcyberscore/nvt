##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_opera_mult_vuln_july08_900001.nasl 4522 2016-11-15 14:52:19Z teissa $
# Description: Opera for Windows Unspecified Code Execution Vulnerabilities July-08
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

tag_impact = "Successful exploitation could grant the remote attacker
        to execute arbitrary malicious code to retrieve random samples
        of the user's memory, which may contain sensitive data.
Impact Level : SYSTEM";

tag_solution = "Upgrade to Opera version 9.51,
 http://www.opera.com/download/";

tag_affected = "Opera Version 5 to 9.50 on Windows (All)";

tag_insight = "The flaws are due to the way the Web Browser handles certain
        canvas functions that can cause the canvas to be painted with
        very small amounts of data constructed from random memory, which
        allows canvas images to be read and analyzed by JavaScript.";


tag_summary = "The remote host is running Opera Web Browser, which is prone
 to multiple vulnerabilities.";
if(description)
{
 script_id(900001);
 script_version("$Revision: 4522 $");
 script_tag(name:"last_modification", value:"$Date: 2016-11-15 15:52:19 +0100 (Tue, 15 Nov 2016) $");
 script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
 script_cve_id("CVE-2008-3078");
 script_bugtraq_id(30068);
 script_copyright("Copyright 2008 SecPod");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
 script_family("General");
 script_name("Opera for Windows Unspecified Code Execution Vulnerabilities July-08");
 script_dependencies("secpod_opera_detection_win_900036.nasl");
 script_require_keys("Opera/Win/Version");
 script_xref(name : "URL" , value : "http://www.opera.com/support/search/view/887/");
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "affected" , value : tag_affected);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "impact" , value : tag_impact);
 exit(0);
}


include("version_func.inc");

OperaVer = get_kb_item("Opera/Win/Version");
if(!OperaVer){
  exit(0);
}

if(version_is_less_equal(version:OperaVer, test_version:"9.50")){
  security_message(0);
}
