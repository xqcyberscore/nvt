###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_mq_detect_lin.nasl 10462 2018-07-09 08:35:44Z ckuersteiner $
#
# IBM Websphere MQ Version Detection (Linux)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811904");
  script_version("$Revision: 10462 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-07-09 10:35:44 +0200 (Mon, 09 Jul 2018) $");
  script_tag(name:"creation_date", value:"2017-09-20 18:25:25 +0530 (Wed, 20 Sep 2017)");
  script_name("IBM Websphere MQ Version Detection (Linux)");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script search for 'dspmqver' and
  queries for IBM Mq version.");

  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

paths = find_bin(prog_name:"dspmqver", sock:sock);
foreach bin (paths)
{
  version = get_bin_version(full_prog_name:chomp(bin), sock:sock, version_argv:"-v",
                            ver_pattern:"Version:     ([0-9.]+)");

  if(version[1] != NULL)
  {
    set_kb_item(name:"IBM/Websphere/MQ/Lin/Ver", value:version[1]);
    set_kb_item(name:"IBM/Websphere/MQ/installed", value: TRUE);

    cpe = build_cpe(value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:ibm:websphere_mq:");
    if(!cpe)
 	cpe = "cpe:/a:ibm:websphere_mq";

    register_product(cpe:cpe, location:bin);
    log_message(data: build_detection_report(app:"IBM Websphere MQ",
                                             version: version[1],
                                             install: bin,
                                             cpe: cpe,
                                             concluded: version[1]));
    close(sock);
    exit(0);
  }
}
close(sock);
