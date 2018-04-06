#################################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_edraw_pdf_viewer_actvx_ctrl_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Edraw PDF Viewer ActiveX Control Insecure Method Vulnerability
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
#################################################################################

tag_solution = "Upgrade to Edraw PDF Viewer Component version to 3.2.0.126
  http://www.edrawsoft.com/pdfviewer.php

  Workaround:
  Set the killbit for the CLSID {44A8091F-8F01-43B7-8CF7-4BBA71E61E04}
  http://support.microsoft.com/kb/240797";

tag_impact = "Attacker may leverage this issue for code execution.
  Impact Level: System/Application";
tag_affected = "Edraw PDF Viewer Component version prior to 3.2.0.126";
tag_insight = "- Error in 'PDFVIEWER.PDFViewerCtrl.1' ActiveX control in 'pdfviewer.ocx', and
    it can exploited via a URL argument to the FtpConnect argument and a target
    filename argument to the 'FtpDownloadFile' method.";
tag_summary = "This host is installed with Edraw PDF Viewer ActiveX Control and
  is prone to Insecure Method vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900379");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2169");
  script_bugtraq_id(35428);
  script_name("Edraw PDF Viewer ActiveX Control Insecure Method Vulnerability");

  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/8986");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35509");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/2009-06/0198.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_activex.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}


key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" +
      "\PDF Viewer Component_is1";
pdfViewName = registry_get_sz(key:key, item:"DisplayName");

if("PDF Viewer Component" >< pdfViewName)
{
  exePath = registry_get_sz(key:key, item:"InstallLocation");
  if(!exePath){
    exit(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                      string:exePath + "pdfviewer.exe");

  pdfviewerVer = GetVer(file:file, share:share);
  if(!pdfviewerVer){
    exit(0);
  }

  # Check for Edraw PDF Viewer version < 3.2.0.126
  if(version_is_less(version:pdfviewerVer, test_version:"3.2.0.126"))
  {
    if(is_killbit_set(clsid:"{44A8091F-8F01-43B7-8CF7-4BBA71E61E04}") == 0){
      security_message(0);
    }
  }
}
