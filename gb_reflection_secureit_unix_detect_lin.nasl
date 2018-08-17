###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_reflection_secureit_unix_detect_lin.nasl 11028 2018-08-17 09:26:08Z cfischer $
#
# Reflection for Secure IT Version Detection (Linux)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800227");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11028 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 11:26:08 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-02-06 13:48:17 +0100 (Fri, 06 Feb 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Reflection for Secure IT Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  script_tag(name:"summary", value:"The script detects the version of Reflections for Secure IT and
  sets the version in KB.");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ssh_func.inc");

SCRIPT_DESC = "Reflection for Secure IT Version Detection (Linux)";

sshPort = get_kb_item("Services/ssh");
if(!sshPort){
  sshPort = 22;
}

secureItVer = eregmatch(pattern:"SSH\-.*ReflectionForSecureIT_([0-9.]+)",
                        string:get_kb_item("SSH/banner/" + sshPort));
if(secureItVer[1] != NULL)
{
  set_kb_item(name:"Reflection/SecureIT/Linux/Ver", value:secureItVer[1]);
  log_message(data:"Reflection for Secure IT version " + secureItVer[1] +
                                     " was detected on the host");

  cpe = build_cpe(value: secureItVer[1], exp:"^([0-9.]+)",base:"cpe:/a:attachmate:reflection_for_secure_it:");
  if(!isnull(cpe))
     register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

}
