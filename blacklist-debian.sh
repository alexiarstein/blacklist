#!/bin/bash

# BLACKLISTER v1.5 
# Autora: Alexia Rivera <lachicadesistemas@gmail.com>
# https://www.github.com/alexiarstein
# GNU GPL 3.0
# ---------------------------------------------------
# Escanea /var/log/auth.log y banea las IPs de intrusos.
# Requiere FIREWALLD.
# ---------------------------------------------------
# UPDATE:
# -------
# Genera un reporte cada hora en /var/log/blacklist/stats.log
# Que contiene la cantidad de intentos de intrusion.
# Quizás resulte útil si se desea generar estadisticas o manipular
# esta data de algún modo u otro.
# ---------------------------------------------------

# Correr como cronjob (root) cada hora
#0 * * * * /bin/bash /opt/blacklist/blacklist.sh > /dev/null 2>&1


# Si /tmp/blacklist.log existe, lo borramos.
rm /tmp/blacklist.log

# correr por unica vez - Escanea los backups y obtiene las IPs.
# Luego comentar.
for i in /var/log/auth.log.*.gz; do zcat $i | grep "Failed password for invalid user" | awk '{print $13}' >> /tmp/tmp_auth_unsorted.log ; done
for i in /var/log/auth.log.*.gz; do zcat $i | grep "Failed password for root from" | awk '{print $11}' >> /tmp/tmp_auth_unsorted.log; done
grep "Failed password for invalid user" /var/log/auth.log.1 | awk '{print $13}' >> /tmp/tmp_auth_unsorted.log
grep "Failed password for root from" /var/log/auth.log.1 | awk '{print $11}' >> /tmp/tmp_auth_unsorted.log
#--------------------------------------------------------------


# Primero generamos un log de lo que ya existe en /etc/firewalld/zones/public.xml
grep "<source address=" /etc/firewalld/zones/public.xml | sed 's/"/,/g' | awk -F ',' '{print $2}'  > /tmp/tmp_zones_public.log

# Luego generamos un nuevo listado con lo que haya en /var/log/auth.log
grep "Failed password for invalid user" /var/log/auth.log | awk '{print $13}' >> /tmp/tmp_auth_unsorted.log
grep "Failed password for root from" /var/log/auth.log | awk '{print $11}' >> /tmp/tmp_auth_unsorted.log

# Eliminamos los duplicados, ya que una misma IP puede haber intentado pegarle al root u otro user inexistente.

sort -u /tmp/tmp_auth_unsorted.log > /tmp/tmp_auth.log

# Limpiamos /tmp/tmp_auth.log para que solo existan IPs en el log.
# Y escribimos el archivo depurado en /tmp/tmp_firewall.log
while IFS= read -r line
do
    # Check if the line is a valid IP address
    if [[ $line =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] ; then
        # If it is, print the IP address
        echo "$line" >> /tmp/tmp_firewall.log
    fi
done < /tmp/tmp_auth.log

# Ahora verificamos si las IPs que acabamos de generar no se encuentran ya blacklisteadas.

while IFS= read -r line
do
    # Check if the line appears in the second file
    if ! grep -q "$line" /tmp/tmp_zones_public.log
    then
        # If not, print the line
        echo "$line" >> /tmp/blacklist.log
    fi
done < /tmp/tmp_firewall.log

rm /tmp/tmp_*
# Por ultimo, solo le pasamos al firewall la lista sin repetidas.
while read i; do
echo -ne "Adding $i to blacklist: "
firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$i' reject"; done < /tmp/blacklist.log
firewall-cmd --reload
conteo=$(echo $(date) | awk '{print $4"-"$3"-"$1"-"$5 $6}')
intrusiones=$(wc -l /tmp/blacklist.log | awk '{print $1}')
echo "$conteo | ${intrusiones} Intentos de Intrusión bloqueados" >> /var/log/blacklist/stats.log
