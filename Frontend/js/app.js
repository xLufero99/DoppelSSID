(() => {
  "use strict";

  const MENSAJE_NO_ADMIN =
    "Esta función necesita permisos de administrador. " +
    "Cierra el programa y vuelve a abrirlo con 'Ejecutar como " +
    "administrador' (Windows) o con sudo (Linux).";
  const MENSAJE_NO_NPCAP =
    "No tienes Npcap instalado (necesario para ver el tráfico " +
    "de otros dispositivos). Sin él, solo puedes ver el consumo de tu " +
    "propio equipo.";
  const MENSAJE_YA_ACTIVO = "Ya hay un monitoreo de tráfico activo.";
  const TEXTO_CONFIRMACION =
    "Vas a interceptar tráfico de TODOS los dispositivos de esta red para medir su consumo. " +
    "Solo continúa si administras esta red. ¿Confirmas?";
  const TIEMPO_ESCANEO = 35000;
  const TIEMPO_NORMAL = 10000;
  const TIEMPO_ESTADO = 5000;
  const INTERVALO_TRAFICO = 2500;

  const estado = {
    monitoreoActivo: false,
    temporizadorTrafico: null,
    pollEnCurso: false,
    controladorEstado: null,
    generacionTrafico: 0,
    modalAccion: null,
    focusAnterior: null,
  };

  const elementos = {
    resumen: document.getElementById("resumen"),
    statSegura: document.getElementById("stat-segura"),
    statPrecaucion: document.getElementById("stat-precaucion"),
    statRiesgo: document.getElementById("stat-riesgo"),
    btnRedes: document.getElementById("btn-redes"),
    estadoRedes: document.getElementById("estado-redes"),
    tablaRedes: document.getElementById("tabla-redes"),
    cuerpoRedes: document.getElementById("cuerpo-redes"),
    btnDispositivos: document.getElementById("btn-dispositivos"),
    estadoDispositivos: document.getElementById("estado-dispositivos"),
    cuerpoDispositivos: document.getElementById("cuerpo-dispositivos"),
    estadoConfiables: document.getElementById("estado-confiables"),
    listaConfiables: document.getElementById("lista-confiables"),
    seccionTrafico: document.getElementById("trafico"),
    indicadorTrafico: document.getElementById("indicador-trafico"),
    textoIndicador: document.getElementById("texto-indicador"),
    capAdmin: document.getElementById("cap-admin"),
    capNpcap: document.getElementById("cap-npcap"),
    estadoTrafico: document.getElementById("estado-trafico"),
    btnIniciarTrafico: document.getElementById("btn-iniciar-trafico"),
    btnDetenerTrafico: document.getElementById("btn-detener-trafico"),
    tituloTablaTrafico: document.getElementById("titulo-tabla-trafico"),
    cuerpoTrafico: document.getElementById("cuerpo-trafico"),
    modal: document.getElementById("modal"),
    modalTitulo: document.getElementById("modal-titulo"),
    modalCuerpo: document.getElementById("modal-cuerpo"),
    modalCancelar: document.getElementById("modal-cancelar"),
    modalConfirmar: document.getElementById("modal-confirmar"),
  };

  function crear(nombre, clase, texto) {
    const elemento = document.createElement(nombre);
    if (clase) {
      elemento.className = clase;
    }
    if (texto !== undefined && texto !== null) {
      elemento.textContent = String(texto);
    }
    return elemento;
  }

  function vaciar(elemento) {
    elemento.replaceChildren();
  }

  function ponerMensaje(elemento, texto, tipo) {
    elemento.textContent = texto;
    elemento.className = tipo ? `mensaje mensaje-${tipo}` : "mensaje";
  }

  async function fetchJson(url, opciones = {}, timeoutMs = TIEMPO_NORMAL) {
    const controlador = new AbortController();
    const temporizador = setTimeout(() => controlador.abort(), timeoutMs);
    const señalExterna = opciones.signal || null;
    const abortarExterno = () => controlador.abort();

    if (señalExterna) {
      if (señalExterna.aborted) {
        controlador.abort();
      } else {
        señalExterna.addEventListener("abort", abortarExterno, { once: true });
      }
    }

    try {
      const cabeceras = { ...(opciones.headers || {}) };
      if (opciones.body !== undefined) {
        cabeceras["Content-Type"] = "application/json";
      }
      const respuesta = await fetch(url, {
        ...opciones,
        cache: "no-store",
        headers: cabeceras,
        signal: controlador.signal,
      });

      let datos = null;
      try {
        datos = await respuesta.json();
      } catch {
        datos = null;
      }

      if (!respuesta.ok) {
        const mensaje =
          datos && typeof datos.error === "string" && datos.error.trim()
            ? datos.error
            : `La solicitud no se pudo completar (${respuesta.status}).`;
        const error = new Error(mensaje);
        error.status = respuesta.status;
        throw error;
      }

      return datos;
    } catch (error) {
      if (error.name === "AbortError") {
        throw new Error("La solicitud tardó demasiado. Inténtalo de nuevo.");
      }
      if (error instanceof TypeError) {
        throw new Error(
          "No se pudo conectar con el servidor local. Comprueba que esté en marcha."
        );
      }
      throw error;
    } finally {
      clearTimeout(temporizador);
      if (señalExterna) {
        señalExterna.removeEventListener("abort", abortarExterno);
      }
    }
  }

  function establecerCarga(boton, enCurso, textoCarga, deshabilitadoBase = false) {
    if (enCurso) {
      if (boton.dataset.textoOriginal === undefined) {
        boton.dataset.textoOriginal = boton.textContent;
      }
      boton.replaceChildren(
        crear("span", "spinner"),
        document.createTextNode(textoCarga)
      );
      boton.disabled = true;
      boton.setAttribute("aria-busy", "true");
      return;
    }

    if (boton.dataset.textoOriginal !== undefined) {
      boton.textContent = boton.dataset.textoOriginal;
      delete boton.dataset.textoOriginal;
    }
    boton.disabled = deshabilitadoBase;
    boton.removeAttribute("aria-busy");
  }

  function actualizarResumen(redes) {
    const conteos = { segura: 0, precaucion: 0, riesgo: 0 };
    for (const red of redes) {
      if (Object.prototype.hasOwnProperty.call(conteos, red.estado)) {
        conteos[red.estado] += 1;
      }
    }
    elementos.statSegura.textContent = conteos.segura;
    elementos.statPrecaucion.textContent = conteos.precaucion;
    elementos.statRiesgo.textContent = conteos.riesgo;
    elementos.resumen.setAttribute(
      "aria-label",
      `${conteos.segura} redes seguras, ${conteos.precaucion} en precaución, ${conteos.riesgo} en riesgo`
    );
  }

  function claseEstado(estadoRed) {
    if (
      estadoRed === "segura" ||
      estadoRed === "precaucion" ||
      estadoRed === "riesgo"
    ) {
      return estadoRed;
    }
    return "oculta";
  }

  function etiquetaEstado(estadoRed) {
    const clase = claseEstado(estadoRed);
    return clase === "precaucion" ? "precaución" : clase;
  }

  function celda(label, clase) {
    const td = crear("td", clase);
    if (label) {
      td.dataset.label = label;
    }
    return td;
  }

  function filaVacia(columnas, texto) {
    const fila = crear("tr", "fila-vacia");
    const td = crear("td", "celda-vacia", texto);
    td.colSpan = columnas;
    fila.append(td);
    return fila;
  }

  function renderRedes(redes) {
    vaciar(elementos.cuerpoRedes);
    elementos.tablaRedes.classList.toggle("tabla-compacta", redes.length >= 20);

    if (!redes.length) {
      elementos.cuerpoRedes.append(
        filaVacia(5, "No se encontraron redes WiFi. Comprueba que el adaptador esté activo.")
      );
      return;
    }

    for (const grupo of redes) {
      const ssid = String(grupo.ssid || "-");
      const bssids = Array.isArray(grupo.redes) ? grupo.redes : [];
      const fila = crear("tr", `fila-red estado-${claseEstado(grupo.estado)}`);

      const tdSsid = celda("SSID");
      tdSsid.append(crear("span", "mono ssid", ssid));
      if (bssids.length > 1) {
        tdSsid.append(crear("span", "bssid-meta", `${bssids.length} BSSID`));
      }
      fila.append(tdSsid);

      const tdOtro = celda("BSSID(s)");
      if (!bssids.length) {
        tdOtro.append(crear("span", "sin-motivos", "Sin BSSID informados."));
      } else {
        const lista = crear("div", "bssid-lista");
        for (const red of bssids) {
          const item = crear("div", "bssid-item");
          item.append(crear("span", "mono", red.bssid || "-"));
          const meta = crear("span", "bssid-meta-lista");
          meta.append(
            crear("span", "", `Canal ${red.canal || 0}`),
            crear("span", "", `Señal ${red.senal || 0}%`)
          );
          const seguridad = [red.autenticacion, red.cifrado]
            .filter(Boolean)
            .join("/");
          if (seguridad) {
            meta.append(crear("span", "", seguridad));
          }
          item.append(meta);
          lista.append(item);
        }
        tdOtro.append(lista);
      }
      fila.append(tdOtro);

      const clase = claseEstado(grupo.estado);
      const tdEstado = celda("Estado");
      tdEstado.append(
        crear("span", `badge badge-${clase}`, etiquetaEstado(grupo.estado))
      );
      fila.append(tdEstado);

      const tdMotivos = celda("Motivos");
      const motivos = Array.isArray(grupo.motivos) ? grupo.motivos : [];
      if (!motivos.length) {
        tdMotivos.append(crear("span", "sin-motivos", "Sin señales específicas."));
      } else {
        const lista = crear("ul", "motivos");
        for (const motivo of motivos) {
          lista.append(crear("li", "", motivo));
        }
        tdMotivos.append(lista);
      }
      fila.append(tdMotivos);

      const tdAccion = celda("Acciones");
      if (ssid === "<oculta>") {
        tdAccion.append(
          crear("span", "sin-motivos", "No disponible para redes ocultas.")
        );
      } else {
        const boton = crear(
          "button",
          "btn btn-fantasma btn-compacto",
          "Confiar en esta red"
        );
        boton.type = "button";
        boton.addEventListener("click", () => pedirConfianza(ssid));
        tdAccion.append(boton);
      }
      fila.append(tdAccion);

      elementos.cuerpoRedes.append(fila);
    }
  }

  async function cargarRedes() {
    establecerCarga(elementos.btnRedes, true, "Escaneando...");
    ponerMensaje(
      elementos.estadoRedes,
      "Escaneando redes WiFi. Esto puede tardar unos segundos."
    );
    try {
      const redes = await fetchJson("/api/redes", {}, TIEMPO_ESCANEO);
      if (!Array.isArray(redes)) {
        throw new Error("La API devolvió un formato inesperado.");
      }
      renderRedes(redes);
      actualizarResumen(redes);
      ponerMensaje(
        elementos.estadoRedes,
        redes.length
          ? `Escaneo actualizado: ${redes.length} redes.`
          : "No se encontraron redes WiFi. Comprueba que el adaptador esté activo.",
        redes.length ? "" : "aviso"
      );
    } catch (error) {
      ponerMensaje(elementos.estadoRedes, error.message, "error");
    } finally {
      establecerCarga(elementos.btnRedes, false);
    }
  }

  function renderDispositivos(dispositivos) {
    vaciar(elementos.cuerpoDispositivos);
    if (!dispositivos.length) {
      elementos.cuerpoDispositivos.append(
        filaVacia(
          4,
          "No se detectaron dispositivos. Intenta de nuevo en unos segundos."
        )
      );
      return;
    }

    for (const dispositivo of dispositivos) {
      const fila = crear("tr", "fila-dispositivo");

      const tdIp = celda("IP");
      tdIp.append(crear("span", "mono", dispositivo.ip || "-"));
      fila.append(tdIp);

      const tdMac = celda("MAC");
      tdMac.append(crear("span", "mono", dispositivo.mac || "-"));
      fila.append(tdMac);

      const tdFabricante = celda("Fabricante");
      tdFabricante.textContent = dispositivo.fabricante || "Desconocido";
      fila.append(tdFabricante);

      const tdEquipo = celda("Equipo");
      if (dispositivo.es_este_equipo) {
        tdEquipo.append(crear("span", "badge badge-neutro", "Este equipo"));
      } else {
        tdEquipo.textContent = "—";
      }
      fila.append(tdEquipo);

      elementos.cuerpoDispositivos.append(fila);
    }
  }

  async function cargarDispositivos() {
    establecerCarga(elementos.btnDispositivos, true, "Buscando...");
    ponerMensaje(
      elementos.estadoDispositivos,
      "Buscando dispositivos en la red local. Esto puede tardar unos segundos."
    );
    try {
      const dispositivos = await fetchJson(
        "/api/dispositivos",
        {},
        TIEMPO_ESCANEO
      );
      if (!Array.isArray(dispositivos)) {
        throw new Error("La API devolvió un formato inesperado.");
      }
      renderDispositivos(dispositivos);
      ponerMensaje(
        elementos.estadoDispositivos,
        dispositivos.length
          ? `Búsqueda terminada: ${dispositivos.length} dispositivos.`
          : "No se detectaron dispositivos. Intenta de nuevo en unos segundos.",
        dispositivos.length ? "" : "aviso"
      );
    } catch (error) {
      ponerMensaje(elementos.estadoDispositivos, error.message, "error");
    } finally {
      establecerCarga(elementos.btnDispositivos, false);
    }
  }

  function renderConfiables(perfiles) {
    vaciar(elementos.listaConfiables);
    if (!perfiles.length) {
      const item = crear(
        "li",
        "celda-vacia",
        "Aún no hay redes de confianza. Marca una red en la tabla para guardarla."
      );
      elementos.listaConfiables.append(item);
      return;
    }

    for (const perfil of perfiles) {
      const ssid = String(perfil.ssid || "-");
      const item = crear("li", "item-confiable");
      const info = crear("div", "item-info");
      info.append(crear("span", "mono item-ssid", ssid));

      const bssids = perfil.bssids && typeof perfil.bssids === "object"
        ? Object.keys(perfil.bssids)
        : [];
      const detalle = crear("div", "item-detalle-lista");
      detalle.append(
        crear("span", "", `${bssids.length} BSSID guardados`)
      );
      const seguridad = [perfil.autenticacion, perfil.cifrado]
        .filter(Boolean)
        .join("/");
      detalle.append(
        crear("span", "", seguridad || "Seguridad no registrada")
      );
      info.append(detalle);

      const boton = crear("button", "btn btn-fantasma btn-compacto", "Quitar");
      boton.type = "button";
      boton.addEventListener("click", () => quitarConfiable(ssid, boton));
      item.append(info, boton);
      elementos.listaConfiables.append(item);
    }
  }

  async function cargarConfiables(mensajeExito) {
    try {
      const perfiles = await fetchJson("/api/confiables");
      if (!Array.isArray(perfiles)) {
        throw new Error("La API devolvió un formato inesperado.");
      }
      renderConfiables(perfiles);
      if (mensajeExito) {
        ponerMensaje(elementos.estadoConfiables, mensajeExito, "exito");
      } else {
        ponerMensaje(
          elementos.estadoConfiables,
          perfiles.length
            ? `${perfiles.length} redes guardadas como confiables.`
            : "Aún no hay redes de confianza. Marca una red en la tabla para guardarla."
        );
      }
    } catch (error) {
      ponerMensaje(elementos.estadoConfiables, error.message, "error");
    }
  }

  async function confiarRed(ssid) {
    await fetchJson("/api/confiables", {
      method: "POST",
      body: JSON.stringify({ ssid }),
    });
    await cargarConfiables(`Confianza guardada para ${ssid}.`);
    await cargarRedes();
  }

  async function quitarConfiable(ssid, boton) {
    establecerCarga(boton, true, "Quitando...");
    try {
      await fetchJson(`/api/confiables/${encodeURIComponent(ssid)}`, {
        method: "DELETE",
      });
      await cargarConfiables(`Se quitó ${ssid} de la lista de confianza.`);
      await cargarRedes();
    } catch (error) {
      ponerMensaje(elementos.estadoConfiables, error.message, "error");
      establecerCarga(boton, false);
    }
  }

  function abrirModal(configuracion) {
    estado.modalAccion = configuracion;
    estado.focusAnterior = document.activeElement;
    elementos.modal.className = `modal ${configuracion.riesgo ? "riesgo" : "accion"}`;
    elementos.modalTitulo.textContent = configuracion.titulo;
    elementos.modalCuerpo.textContent = configuracion.cuerpo;
    elementos.modalConfirmar.textContent = configuracion.confirmar;
    elementos.modalConfirmar.className = `btn ${
      configuracion.riesgo ? "btn-peligro" : "btn-primario"
    }`;
    elementos.modalConfirmar.disabled = false;
    elementos.modalCancelar.disabled = false;
    elementos.modal.showModal();
    elementos.modalCancelar.focus();
  }

  function configurarModal() {
    elementos.modalCancelar.addEventListener("click", () => {
      elementos.modal.close();
    });

    elementos.modal.addEventListener("close", () => {
      estado.modalAccion = null;
      if (
        estado.focusAnterior &&
        document.contains(estado.focusAnterior) &&
        !estado.focusAnterior.hidden
      ) {
        estado.focusAnterior.focus();
      }
    });

    elementos.modalConfirmar.addEventListener("click", async () => {
      const accion = estado.modalAccion;
      if (!accion) {
        return;
      }
      const textoOriginal = elementos.modalConfirmar.textContent;
      elementos.modalConfirmar.disabled = true;
      elementos.modalCancelar.disabled = true;
      elementos.modalConfirmar.textContent = "Confirmando…";
      try {
        await accion.alConfirmar();
        elementos.modal.close();
      } catch (error) {
        ponerMensaje(
          accion.destinoError || elementos.estadoTrafico,
          error.message,
          "error"
        );
        elementos.modal.close();
      } finally {
        elementos.modalConfirmar.disabled = false;
        elementos.modalCancelar.disabled = false;
        elementos.modalConfirmar.textContent = textoOriginal;
      }
    });
  }

  function pedirConfianza(ssid) {
    abrirModal({
      titulo: "Confiar en esta red",
      cuerpo: `Hazlo solo si estás seguro de estar en tu red real. Se guardarán los BSSID actuales de ${ssid}.`,
      confirmar: "Confiar en esta red",
      riesgo: false,
      destinoError: elementos.estadoRedes,
      alConfirmar: () => confiarRed(ssid),
    });
  }

  function confirmarInicioTrafico() {
    abrirModal({
      titulo: "Confirmar monitoreo de tráfico",
      cuerpo: TEXTO_CONFIRMACION,
      confirmar: "Iniciar monitoreo",
      riesgo: true,
      destinoError: elementos.estadoTrafico,
      alConfirmar: iniciarMonitoreo,
    });
  }

  async function cargarCapacidades(mantenerMensaje = false) {
    if (estado.monitoreoActivo) {
      return;
    }
    elementos.btnIniciarTrafico.disabled = true;
    elementos.capAdmin.textContent = "Comprobando…";
    elementos.capNpcap.textContent = "Comprobando…";
    if (!mantenerMensaje) {
      ponerMensaje(elementos.estadoTrafico, "Comprobando permisos…");
    }

    try {
      const capacidades = await fetchJson("/api/trafico/capacidades");
      elementos.capAdmin.textContent = capacidades.es_administrador ? "sí" : "no";
      elementos.capNpcap.textContent = capacidades.npcap_instalado
        ? "instalado"
        : "no instalado";

      if (!capacidades.es_administrador) {
        if (!mantenerMensaje) {
          ponerMensaje(elementos.estadoTrafico, MENSAJE_NO_ADMIN, "error");
        }
        return;
      }
      if (!capacidades.npcap_instalado) {
        if (!mantenerMensaje) {
          ponerMensaje(elementos.estadoTrafico, MENSAJE_NO_NPCAP, "aviso");
        }
        return;
      }

      if (!mantenerMensaje) {
        ponerMensaje(
          elementos.estadoTrafico,
          "Listo para medir el tráfico de tu red."
        );
      }
      elementos.btnIniciarTrafico.disabled = false;
    } catch (error) {
      elementos.capAdmin.textContent = "No disponible";
      elementos.capNpcap.textContent = "No disponible";
      if (!mantenerMensaje) {
        ponerMensaje(elementos.estadoTrafico, error.message, "error");
      }
    }
  }

  function limpiarPolling() {
    estado.generacionTrafico += 1;
    if (estado.temporizadorTrafico !== null) {
      clearInterval(estado.temporizadorTrafico);
      estado.temporizadorTrafico = null;
    }
    if (estado.controladorEstado) {
      estado.controladorEstado.abort();
      estado.controladorEstado = null;
    }
    estado.pollEnCurso = false;
  }

  function renderTrafico(resultados, titulo) {
    elementos.tituloTablaTrafico.textContent = titulo;
    vaciar(elementos.cuerpoTrafico);
    const filas = Array.isArray(resultados) ? resultados : [];

    if (!filas.length) {
      elementos.cuerpoTrafico.append(
        filaVacia(5, "Esperando las primeras muestras de tráfico.")
      );
      return;
    }

    for (const fila of filas) {
      const ip = String(fila.ip || "-");
      const porcentaje = Math.max(
        0,
        Math.min(100, Math.trunc(Number(fila.porcentaje) || 0))
      );
      const kb = (Number(fila.bytes) || 0) / 1024;
      const filaTabla = crear("tr", "fila-trafico");

      const tdIp = celda("IP");
      tdIp.append(crear("span", "mono", ip));
      if (fila.es_este_equipo) {
        tdIp.append(crear("span", "bssid-meta", "Este equipo"));
      }
      filaTabla.append(tdIp);

      const tdFabricante = celda("Fabricante");
      tdFabricante.textContent = fila.fabricante || "Desconocido";
      filaTabla.append(tdFabricante);

      const tdKb = celda("KB");
      tdKb.append(crear("span", "mono-sm", kb.toFixed(1).replace(".", ",")));
      filaTabla.append(tdKb);

      const tdPorcentaje = celda("%");
      tdPorcentaje.append(crear("span", "mono-sm", String(porcentaje)));
      filaTabla.append(tdPorcentaje);

      const tdBarra = celda("Participación");
      const barra = crear("div", "barra");
      const relleno = crear("span");
      relleno.style.width = `${porcentaje}%`;
      barra.append(relleno);
      barra.setAttribute("role", "img");
      barra.setAttribute("aria-label", `${porcentaje} % del tráfico`);
      tdBarra.append(barra);
      filaTabla.append(tdBarra);

      elementos.cuerpoTrafico.append(filaTabla);
    }
  }

  function activarMonitoreo() {
    limpiarPolling();
    estado.monitoreoActivo = true;
    estado.generacionTrafico += 1;
    const generacion = estado.generacionTrafico;

    elementos.seccionTrafico.classList.add("monitoreo-activo");
    elementos.indicadorTrafico.classList.add("activo");
    elementos.textoIndicador.textContent = "En vivo";
    elementos.btnIniciarTrafico.hidden = true;
    elementos.btnDetenerTrafico.hidden = false;
    elementos.btnDetenerTrafico.disabled = false;
    elementos.btnDetenerTrafico.textContent = "Detener monitoreo";
    renderTrafico([], "Tráfico en vivo");

    estado.temporizadorTrafico = setInterval(
      () => pollTrafico(generacion),
      INTERVALO_TRAFICO
    );
    pollTrafico(generacion);
  }

  function desactivarMonitoreo(resumen) {
    limpiarPolling();
    estado.monitoreoActivo = false;
    elementos.seccionTrafico.classList.remove("monitoreo-activo");
    elementos.indicadorTrafico.classList.remove("activo");
    elementos.textoIndicador.textContent = "Detenido";
    elementos.btnDetenerTrafico.hidden = true;
    elementos.btnDetenerTrafico.disabled = false;
    elementos.btnDetenerTrafico.textContent = "Detener monitoreo";
    elementos.btnIniciarTrafico.hidden = false;
    renderTrafico(resumen, "Resumen final");
    cargarCapacidades(true);
  }

  async function pollTrafico(generacion) {
    if (
      !estado.monitoreoActivo ||
      generacion !== estado.generacionTrafico ||
      estado.pollEnCurso
    ) {
      return;
    }

    estado.pollEnCurso = true;
    const controlador = new AbortController();
    estado.controladorEstado = controlador;

    try {
      const resultados = await fetchJson(
        "/api/trafico/estado",
        { signal: controlador.signal },
        TIEMPO_ESTADO
      );
      if (
        !estado.monitoreoActivo ||
        generacion !== estado.generacionTrafico ||
        !Array.isArray(resultados)
      ) {
        return;
      }
      renderTrafico(resultados, "Tráfico en vivo");
    } catch (error) {
      if (
        !estado.monitoreoActivo ||
        generacion !== estado.generacionTrafico
      ) {
        return;
      }
      if (error.status === 404) {
        const mensaje = error.message;
        desactivarMonitoreo([]);
        ponerMensaje(elementos.estadoTrafico, mensaje, "aviso");
        return;
      }
      ponerMensaje(elementos.estadoTrafico, error.message, "error");
    } finally {
      if (estado.controladorEstado === controlador) {
        estado.controladorEstado = null;
      }
      estado.pollEnCurso = false;
    }
  }

  async function iniciarMonitoreo() {
    elementos.btnIniciarTrafico.disabled = true;
    ponerMensaje(
      elementos.estadoTrafico,
      "Iniciando monitoreo. Esto puede tardar unos segundos..."
    );
    try {
      await fetchJson("/api/trafico/iniciar", {
        method: "POST",
        body: JSON.stringify({ confirmo_red_propia: true }),
      });
      activarMonitoreo();
      ponerMensaje(
        elementos.estadoTrafico,
        "Monitoreo activo. Se está interceptando el tráfico de esta red.",
        "aviso"
      );
    } catch (error) {
      if (error.message === MENSAJE_YA_ACTIVO) {
        activarMonitoreo();
        ponerMensaje(elementos.estadoTrafico, error.message, "aviso");
        return;
      }
      ponerMensaje(elementos.estadoTrafico, error.message, "error");
      await cargarCapacidades(true);
    }
  }

  async function detenerMonitoreo() {
    elementos.btnDetenerTrafico.disabled = true;
    elementos.btnDetenerTrafico.textContent = "Deteniendo...";
    try {
      const respuesta = await fetchJson("/api/trafico/detener", {
        method: "POST",
      });
      const resumen =
        respuesta && Array.isArray(respuesta.resumen) ? respuesta.resumen : [];
      desactivarMonitoreo(resumen);
      ponerMensaje(
        elementos.estadoTrafico,
        "Monitoreo detenido. La tabla muestra el resumen final."
      );
    } catch (error) {
      if (error.status === 404) {
        const mensaje = error.message;
        desactivarMonitoreo([]);
        ponerMensaje(elementos.estadoTrafico, mensaje, "aviso");
        return;
      }
      ponerMensaje(elementos.estadoTrafico, error.message, "error");
      elementos.btnDetenerTrafico.disabled = false;
      elementos.btnDetenerTrafico.textContent = "Detener monitoreo";
    }
  }

  function configurarNavegacion() {
    const enlaces = Array.from(document.querySelectorAll(".nav-enlace"));
    if (!enlaces.length || !("IntersectionObserver" in window)) {
      return;
    }
    const secciones = enlaces
      .map((enlace) => document.querySelector(enlace.getAttribute("href")))
      .filter(Boolean);
    if (!secciones.length) {
      return;
    }

    const observador = new IntersectionObserver(
      (entradas) => {
        const visibles = entradas
          .filter((entrada) => entrada.isIntersecting)
          .sort((a, b) => b.intersectionRatio - a.intersectionRatio);
        if (!visibles.length) {
          return;
        }
        const href = `#${visibles[0].target.id}`;
        for (const enlace of enlaces) {
          enlace.classList.toggle("activo", enlace.getAttribute("href") === href);
        }
      },
      { rootMargin: "-88px 0px -60% 0px", threshold: [0, 0.1, 0.5] }
    );
    for (const seccion of secciones) {
      observador.observe(seccion);
    }
  }

  function inicializar() {
    configurarModal();
    configurarNavegacion();
    renderTrafico([], "Tráfico en vivo");
    ponerMensaje(
      elementos.estadoDispositivos,
      "Pulsa Buscar dispositivos para ver la red local."
    );

    elementos.btnRedes.addEventListener("click", cargarRedes);
    elementos.btnDispositivos.addEventListener("click", cargarDispositivos);
    elementos.btnIniciarTrafico.addEventListener(
      "click",
      confirmarInicioTrafico
    );
    elementos.btnDetenerTrafico.addEventListener("click", detenerMonitoreo);

    window.addEventListener("pagehide", () => {
      limpiarPolling();
      if (estado.monitoreoActivo && typeof navigator.sendBeacon === "function") {
        try {
          navigator.sendBeacon(
            "/api/trafico/detener",
            new Blob([], { type: "application/json" })
          );
        } catch {
          return;
        }
      }
      estado.monitoreoActivo = false;
    });

    cargarRedes();
    cargarConfiables();
    cargarCapacidades();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", inicializar);
  } else {
    inicializar();
  }
})();
