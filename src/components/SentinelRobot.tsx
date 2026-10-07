import { useEffect, useRef } from "react";

/** Vector artwork with frame-coalesced, cursor-relative eye movement. */
export function SentinelRobot({ paused = false }: { paused?: boolean }) {
  const svgRef = useRef<SVGSVGElement>(null);
  const headRef = useRef<SVGGElement>(null);
  const eyesRef = useRef<SVGGElement>(null);

  useEffect(() => {
    const svg = svgRef.current;
    const win = svg?.ownerDocument.defaultView;
    if (!svg || !win) return;
    let frame = 0;
    let x = 0;
    let y = 0;
    const paint = () => {
      frame = 0;
      eyesRef.current?.setAttribute("transform", `translate(${x * 7} ${y * 5})`);
      headRef.current?.setAttribute("transform", `translate(${x * 2} ${y * 2}) rotate(${x * 3} 120 84)`);
    };
    const move = (event: MouseEvent) => {
      const bounds = svg.getBoundingClientRect();
      x = Math.max(-1, Math.min(1, (event.clientX - bounds.left - bounds.width / 2) / 180));
      y = Math.max(-1, Math.min(1, (event.clientY - bounds.top - bounds.height * 0.45) / 180));
      if (!frame) frame = win.requestAnimationFrame(paint);
    };
    const reset = () => {
      x = 0;
      y = 0;
      if (!frame) frame = win.requestAnimationFrame(paint);
    };
    win.addEventListener("mousemove", move, { passive: true });
    win.addEventListener("blur", reset);
    svg.ownerDocument.addEventListener("mouseleave", reset);
    return () => {
      win.removeEventListener("mousemove", move);
      win.removeEventListener("blur", reset);
      svg.ownerDocument.removeEventListener("mouseleave", reset);
      win.cancelAnimationFrame(frame);
    };
  }, []);

  return (
    <div className={`robot-stage shrink-0 ${paused ? "robot-paused" : ""}`}>
      <svg ref={svgRef} className="sentinel-robot" viewBox="0 0 240 170" role="img" aria-label="Robottino Sentinel con occhi che seguono il cursore">
        <ellipse className="robot-ground" cx="120" cy="154" rx="43" ry="4" />
        <path className="robot-body" d="M99 117 Q120 108 141 117 L148 141 Q120 152 92 141Z" />
        <path className="robot-seam" d="M105 138 Q120 142 135 138" />
        <rect className="robot-emblem" x="116" y="124" width="8" height="8" rx="3" />
        <g ref={headRef} data-robot-head>
          <path className="robot-antenna" d="M120 44V30" />
          <circle className="robot-beacon" cx="120" cy="26" r="4" />
          <rect className="robot-ear" x="61" y="69" width="14" height="30" rx="6" />
          <rect className="robot-ear" x="165" y="69" width="14" height="30" rx="6" />
          <rect className="robot-shell" x="70" y="44" width="100" height="75" rx="26" />
          <path className="robot-highlight" d="M89 51H149" />
          <rect className="robot-visor" x="79" y="58" width="82" height="45" rx="17" />
          <g ref={eyesRef} data-robot-eyes>
            <rect className="robot-eye" x="95" y="70" width="13" height="20" rx="6.5" />
            <rect className="robot-eye" x="132" y="70" width="13" height="20" rx="6.5" />
            <path className="robot-smile" d="M115 91Q120 95 125 91" />
          </g>
          <path className="robot-cheek" d="M85 109H92M148 109H155" />
        </g>
      </svg>
    </div>
  );
}