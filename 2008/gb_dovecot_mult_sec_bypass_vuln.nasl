###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dovecot_mult_sec_bypass_vuln.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# Dovecot ACL Plugin Security Bypass Vulnerabilities
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
###############################################################################

tag_impact = "Successful attack could allow malicious people to bypass certain
  security restrictions or manipulate certain data.
  Impact Level: Application";
tag_affected = "Dovecot versions prior to 1.1.4 on Linux";
tag_insight = "The flaws are due to,
  - the ACL plugin interprets negative access rights as positive access rights,
    potentially giving an unprivileged user access to restricted resources.
  - an error in the ACL plugin when imposing mailbox creation restrictions to
    to create parent/child/child mailboxes.";
tag_solution = "Upgrade to Dovecot version 1.1.4
  http://www.dovecot.org/download.html";
tag_summary = "This host has Dovecot ACL Plugin installed and is prone to
  multiple security bypass vulnerabilities.";


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800030");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-10-17 14:35:03 +0200 (Fri, 17 Oct 2008)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2008-4577", "CVE-2008-4578");
  script_bugtraq_id(31587);
  script_name("Dovecot ACL Plugin Security Bypass Vulnerabilities");
  script_xref(name : "URL" , value : "http://www.frsirt.com/english/advisories/2008/2745");
  script_xref(name : "URL" , value : "http://www.dovecot.org/list/dovecot-news/2008-October/000085.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("gather-package-list.nasl");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);

  # This NVT is broken in many ways...
  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit( 66 );

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

getPath = find_bin(prog_name:"dovecot", sock:sock);
foreach binary_File (getPath)
{
  doveVer = get_bin_version(full_prog_name:chomp(binary_File), version_argv:"--version",
                            ver_pattern:"[0-9.]+", sock:sock);
  if(doveVer)
  {
    if(version_is_less(version:doveVer[0], test_version:"1.1.4")){
      security_message(0);
    }
    ssh_close_connection();
    exit(0);
  }
}
ssh_close_connection();
