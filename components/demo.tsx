import { HandwritingSvg } from "@/components/ui/handwriting-svg";

export default function Default() {
  return (
    <div className="flex min-h-[320px] w-full items-center justify-center">
      <HandwritingSvg
        text="Hello"
        width={320}
        height={160}
        fontSize={72}
        strokeWidth={1}
        duration={2.5}
        className="text-rose-500"
      />
    </div>
  );
}
